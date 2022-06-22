package cardano

import (
	"encoding/hex"
	"fmt"

	"github.com/echovl/cardano-go/crypto"
	"golang.org/x/crypto/blake2b"
)

const utxoEntrySizeWithoutVal = 27

// UTxO is a Cardano Unspent Transaction Output.
type UTxO struct {
	TxHash  Hash32
	Spender Address
	Amount  *Value
	Index   uint64
}

// Tx is a Cardano transaction.
type Tx struct {
	_             struct{}       `cbor:",toarray"`
	Body          TxBody         `json:"body"`
	WitnessSet    WitnessSet     `json:"witness_set"`
	IsValid       bool           `json:"is_valid"`
	AuxiliaryData *AuxiliaryData `json:"auxiliary_data"`
}

// Bytes returns the CBOR encoding of the transaction as bytes.
func (tx *Tx) Bytes() []byte {
	bytes, err := cborEnc.Marshal(tx)
	if err != nil {
		panic(err)
	}
	return bytes
}

// Hex returns the CBOR encoding of the transaction as hex.
func (tx Tx) Hex() string {
	return hex.EncodeToString(tx.Bytes())
}

// Hash returns the transaction body hash using blake2b.
func (tx *Tx) Hash() (Hash32, error) {
	return tx.Body.Hash()
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (tx *Tx) UnmarshalCBOR(data []byte) error {
	type rawTx Tx
	var rt rawTx

	err := cborDec.Unmarshal(data, &rt)
	if err != nil {
		return err
	}
	tx.Body = rt.Body
	tx.WitnessSet = rt.WitnessSet
	tx.IsValid = rt.IsValid
	tx.AuxiliaryData = rt.AuxiliaryData

	return nil
}

// MarshalCBOR implements cbor.Marshaler.
func (tx *Tx) MarshalCBOR() ([]byte, error) {
	type rawTx Tx
	return cborEnc.Marshal(rawTx(*tx))
}

// WitnessSet represents the witnesses of the transaction.
type WitnessSet struct {
	VKeyWitnessSet []VKeyWitness  `cbor:"0,keyasint,omitempty"`
	Scripts        []NativeScript `cbor:"1,keyasint,omitempty"`
}

// VKeyWitness is a witnesss that uses verification keys.
type VKeyWitness struct {
	_         struct{}      `cbor:",toarray" json:"-"`
	VKey      crypto.PubKey // ed25519 public key
	Signature []byte        // ed25519 signature
}

// TxInput is the transaction input.
type TxInput struct {
	_      struct{} `cbor:",toarray" json:"-"`
	TxHash Hash32
	Index  uint64
	Amount *Value `cbor:"-"`
}

// NewTxInput creates a new instance of TxInput
func NewTxInput(txHash Hash32, index uint, amount *Value) *TxInput {
	return &TxInput{TxHash: txHash, Index: uint64(index), Amount: amount}
}

// String implements stringer.
func (t TxInput) String() string {
	return fmt.Sprintf("{TxHash: %v, Index: %v, Amount: %v}", t.TxHash, t.Index, t.Amount)
}

// TxInput is the transaction output.
type TxOutput struct {
	_       struct{} `cbor:",toarray" json:"-"`
	Address Address
	Amount  *Value
}

// NewTxOutput creates a new instance of TxOutput
func NewTxOutput(addr Address, amount *Value) *TxOutput {
	return &TxOutput{Address: addr, Amount: amount}
}

func (t TxOutput) String() string {
	return fmt.Sprintf("{Address: %v, Amount: %v}", t.Address, t.Amount)
}

type TxBody struct {
	Inputs  []*TxInput  `cbor:"0,keyasint" json:"inputs,omitempty"`
	Outputs []*TxOutput `cbor:"1,keyasint" json:"outputs,omitempty"`
	Fee     Coin        `cbor:"2,keyasint" json:"fee,omitempty"`

	// Optionals
	TTL                   Uint64        `cbor:"3,keyasint,omitempty" json:"ttl,omitempty"`
	Certificates          []Certificate `cbor:"4,keyasint,omitempty" json:"certificates,omitempty"`
	Withdrawals           interface{}   `cbor:"5,keyasint,omitempty" json:"withdrawals,omitempty"` // unsupported
	Update                interface{}   `cbor:"6,keyasint,omitempty" json:"update,omitempty"`      // unsupported
	AuxiliaryDataHash     *Hash32       `cbor:"7,keyasint,omitempty" json:"auxiliary_data_hash,omitempty"`
	ValidityIntervalStart Uint64        `cbor:"8,keyasint,omitempty" json:"validity_interval_start,omitempty"`
	Mint                  *Mint         `cbor:"9,keyasint,omitempty" json:"mint,omitempty"`
	ScriptDataHash        *Hash32       `cbor:"10,keyasint,omitempty" json:"script_data_hash,omitempty"`
	Collateral            []TxInput     `cbor:"11,keyasint,omitempty" json:"collateral,omitempty"`
	RequiredSigners       []AddrKeyHash `cbor:"12,keyasint,omitempty" json:"required_signers,omitempty"`
	NetworkID             Uint64        `cbor:"13,keyasint,omitempty" json:"network_id,omitempty"`
}

// Hash returns the transaction body hash using blake2b256.
func (body *TxBody) Hash() (Hash32, error) {
	bytes, err := cborEnc.Marshal(body)
	if err != nil {
		return Hash32{}, err
	}
	hash := blake2b.Sum256(bytes)
	return hash[:], nil
}
