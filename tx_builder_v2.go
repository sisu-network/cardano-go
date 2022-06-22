package cardano

import (
	"errors"
	"fmt"
	"math"

	"github.com/decred/dcrd/dcrec/edwards/v2"

	"golang.org/x/crypto/blake2b"
)

type TxBuilderV2 struct {
	tx       *Tx
	protocol *ProtocolParams
	pkeys    []*edwards.PrivateKey
}

// NewTxBuilder returns a new instance of TxBuilder.
func NewTxBuilderV2(protocol *ProtocolParams) *TxBuilderV2 {
	return &TxBuilderV2{
		protocol: protocol,
		pkeys:    []*edwards.PrivateKey{},
		tx: &Tx{
			IsValid: true,
		},
	}
}

// AddInputs adds inputs to the transaction.
func (tb *TxBuilderV2) AddInputs(inputs ...*TxInput) {
	tb.tx.Body.Inputs = append(tb.tx.Body.Inputs, inputs...)
}

// AddOutputs adds outputs to the transaction.
func (tb *TxBuilderV2) AddOutputs(outputs ...*TxOutput) {
	tb.tx.Body.Outputs = append(tb.tx.Body.Outputs, outputs...)
}

// SetTtl sets the transaction's time to live.
func (tb *TxBuilderV2) SetTTL(ttl uint64) {
	tb.tx.Body.TTL = NewUint64(ttl)
}

// SetFee sets the transactions's fee.
func (tb *TxBuilderV2) SetFee(fee Coin) {
	tb.tx.Body.Fee = fee
}

// AddAuxiliaryData adds auxiliary data to the transaction.
func (tb *TxBuilderV2) AddAuxiliaryData(data *AuxiliaryData) {
	tb.tx.AuxiliaryData = data
}

// AddCertificate adds a certificate to the transaction.
func (tb *TxBuilderV2) AddCertificate(cert Certificate) {
	tb.tx.Body.Certificates = append(tb.tx.Body.Certificates, cert)
}

// AddNativeScript adds a native script to the transaction.
func (tb *TxBuilderV2) AddNativeScript(script NativeScript) {
	tb.tx.WitnessSet.Scripts = append(tb.tx.WitnessSet.Scripts, script)
}

// Mint adds a new multiasset to mint.
func (tb *TxBuilderV2) Mint(asset *Mint) {
	tb.tx.Body.Mint = asset
}

// AddChangeIfNeeded calculates the required fee for the transaction and adds
// an aditional output for the change if there is any.
// This assumes that the inputs-outputs are defined and signing keys are present.
func (tb *TxBuilderV2) AddChangeIfNeeded(changeAddr Address) error {
	inputAmount, outputAmount := tb.calculateAmounts()

	// Set a temporary realistic fee in order to serialize a valid transaction
	tb.tx.Body.Fee = 200000
	if _, err := tb.build2(); err != nil {
		return err
	}

	minFee := tb.calculateMinFee()
	outputAmount = outputAmount.Add(NewValue(minFee))

	if inputOutputCmp := inputAmount.Cmp(outputAmount); inputOutputCmp == -1 || inputOutputCmp == 2 {
		return fmt.Errorf(
			"insuficient input in transaction, got %v want atleast %v",
			inputAmount,
			outputAmount,
		)
	} else if inputOutputCmp == 0 {
		tb.tx.Body.Fee = minFee
		return nil
	}

	// Construct change output
	changeAmount := inputAmount.Sub(outputAmount)
	changeOutput := NewTxOutput(changeAddr, changeAmount)

	changeMinCoins := tb.MinCoinsForTxOut(changeOutput)
	if changeAmount.Coin < changeMinCoins {
		if changeAmount.OnlyCoin() {
			tb.tx.Body.Fee = minFee + changeAmount.Coin // burn change
			return nil
		}
		return fmt.Errorf(
			"insuficient input for change output with multiassets, got %v want %v",
			inputAmount.Coin,
			inputAmount.Coin+changeMinCoins-changeAmount.Coin,
		)
	}

	tb.tx.Body.Outputs = append([]*TxOutput{changeOutput}, tb.tx.Body.Outputs...)

	newMinFee := tb.calculateMinFee()
	changeAmount.Coin = changeAmount.Coin + minFee - newMinFee
	if changeAmount.Coin < changeMinCoins {
		if changeAmount.OnlyCoin() {
			tb.tx.Body.Fee = newMinFee + changeAmount.Coin // burn change
			tb.tx.Body.Outputs = tb.tx.Body.Outputs[1:]    // remove change output
			return nil
		}
		return fmt.Errorf(
			"insuficient input for change output with multiassets, got %v want %v",
			inputAmount.Coin,
			changeMinCoins,
		)
	}

	tb.tx.Body.Fee = newMinFee

	return nil
}

func (tb *TxBuilderV2) calculateAmounts() (*Value, *Value) {
	input, output := NewValue(0), NewValue(tb.totalDeposits())
	for _, in := range tb.tx.Body.Inputs {
		input = input.Add(in.Amount)
	}
	for _, out := range tb.tx.Body.Outputs {
		output = output.Add(out.Amount)
	}
	if tb.tx.Body.Mint != nil {
		input = input.Add(NewValueWithAssets(0, tb.tx.Body.Mint.MultiAsset()))
	}
	return input, output
}

func (tb *TxBuilderV2) totalDeposits() Coin {
	certs := tb.tx.Body.Certificates
	var deposit Coin
	if len(certs) != 0 {
		for _, cert := range certs {
			if cert.Type == StakeRegistration {
				deposit += tb.protocol.KeyDeposit
			}
		}
	}
	return deposit
}

// MinFee computes the minimal fee required for the transaction.
// This assumes that the inputs-outputs are defined and signing keys are present.
func (tb *TxBuilderV2) MinFee() (Coin, error) {
	// Set a temporary realistic fee in order to serialize a valid transaction
	currentFee := tb.tx.Body.Fee
	tb.tx.Body.Fee = 200000
	if _, err := tb.build(); err != nil {
		return 0, err
	}
	minFee := tb.calculateMinFee()
	tb.tx.Body.Fee = currentFee
	return minFee, nil
}

// MinCoinsForTxOut computes the minimal amount of coins required for a given transaction output.
func (tb *TxBuilderV2) MinCoinsForTxOut(txOut *TxOutput) Coin {
	var size uint
	if txOut.Amount.OnlyCoin() {
		size = 1
	} else {
		numAssets := txOut.Amount.MultiAsset.numAssets()
		assetsLength := txOut.Amount.MultiAsset.assetsLength()
		numPIDs := txOut.Amount.MultiAsset.numPIDs()

		size = 6 + uint(math.Floor(
			float64(numAssets*12+assetsLength+numPIDs*28+7)/8,
		))
	}
	return Coin(utxoEntrySizeWithoutVal+size) * tb.protocol.CoinsPerUTXOWord
}

// calculateMinFee computes the minimal fee required for the transaction.
func (tb *TxBuilderV2) calculateMinFee() Coin {
	txBytes := tb.tx.Bytes()
	txLength := uint64(len(txBytes))
	return tb.protocol.MinFeeA*Coin(txLength) + tb.protocol.MinFeeB
}

// Sign adds signing keys to create signatures for the witness set.
func (tb *TxBuilderV2) Sign(privateKeys ...*edwards.PrivateKey) {
	tb.pkeys = append(tb.pkeys, privateKeys...)
}

// Build creates a new transaction using the inputs, outputs and keys provided.
func (tb *TxBuilderV2) Build() (*Tx, error) {
	inputAmount, outputAmount := tb.calculateAmounts()
	outputAmount = outputAmount.Add(NewValue(tb.tx.Body.Fee))

	if inputOutputCmp := outputAmount.Cmp(inputAmount); inputOutputCmp == 1 || inputOutputCmp == 2 {
		return nil, fmt.Errorf(
			"insuficient input in transaction, got %v want %v",
			inputAmount,
			outputAmount,
		)
	} else if inputOutputCmp == -1 {
		return nil, fmt.Errorf(
			"fee too small, got %v want %v",
			tb.tx.Body.Fee,
			inputAmount.Sub(outputAmount),
		)
	}

	return tb.build()
}

func (tb *TxBuilderV2) build() (*Tx, error) {
	if len(tb.pkeys) == 0 {
		return nil, errors.New("missing signing keys")
	}

	if err := tb.buildBody(); err != nil {
		return nil, err
	}

	txHash, err := tb.tx.Hash()
	if err != nil {
		return nil, err
	}

	vkeyWitnsessSet := make([]VKeyWitness, len(tb.pkeys))
	for i, pkey := range tb.pkeys {
		publicKey := pkey.PubKey()
		sig, err := pkey.Sign(txHash[:])
		if err != nil {
			return nil, err
		}
		signature := sig.Serialize()
		witness := VKeyWitness{VKey: publicKey.Serialize(), Signature: signature}
		vkeyWitnsessSet[i] = witness
	}
	tb.tx.WitnessSet.VKeyWitnessSet = vkeyWitnsessSet

	return tb.tx, nil
}

///////// EDIT

func (tb *TxBuilderV2) Build2() (*Tx, error) {
	inputAmount, outputAmount := tb.calculateAmounts()
	outputAmount = outputAmount.Add(NewValue(tb.tx.Body.Fee))

	if inputOutputCmp := outputAmount.Cmp(inputAmount); inputOutputCmp == 1 || inputOutputCmp == 2 {
		return nil, fmt.Errorf(
			"insuficient input in transaction, got %v want %v",
			inputAmount,
			outputAmount,
		)
	} else if inputOutputCmp == -1 {
		return nil, fmt.Errorf(
			"fee too small, got %v want %v",
			tb.tx.Body.Fee,
			inputAmount.Sub(outputAmount),
		)
	}

	return tb.build2()
}

func (tb *TxBuilderV2) build2() (*Tx, error) {
	if err := tb.buildBody(); err != nil {
		return nil, err
	}

	vkeyWitnsessSet := make([]VKeyWitness, 1)
	for i := range tb.tx.Body.Inputs {
		witness := VKeyWitness{VKey: make([]byte, 32), Signature: make([]byte, 64)}
		vkeyWitnsessSet[i] = witness
	}
	tb.tx.WitnessSet.VKeyWitnessSet = vkeyWitnsessSet

	return tb.tx, nil
}

///////// END OF EDIT

func (tb *TxBuilderV2) buildBody() error {
	if tb.tx.AuxiliaryData != nil {
		auxBytes, err := cborEnc.Marshal(tb.tx.AuxiliaryData)
		if err != nil {
			return err
		}
		auxHash := blake2b.Sum256(auxBytes)
		auxHash32 := Hash32(auxHash[:])
		tb.tx.Body.AuxiliaryDataHash = &auxHash32
	}
	return nil
}
