package toxics

import (
	"encoding/binary"
	"unicode/utf16"
	"github.com/Shopify/toxiproxy/stream"
)

// The MSSQLToxic kills a connection once it sees a certain SQL Batch or RPC call
type MSSQLToxic struct {
	// Times in milliseconds
	MSSQLBatch string `json:"mssqlBatch"`
}

func (t *MSSQLToxic) DataMatchBatch(bytes []byte) bool {

	//Message type sql batch
	if bytes[0] != 0x01 {
		return false
	}

	//Status is End Of Message (assuming short batches right now)
	if bytes[1] != 0x01 {
		return false
	}

	allHeadersLengthBytes := make([]byte, 4)
	copy(bytes[8:12, allHeadersLengthBytes[:]])
	allHeadersLength := binary.LittleEndian.Uint32(allHeadersLengthBytes)
	startOfUnicode := 8 + allHeadersLength
	bytesToMatch := utf16.Encode(t.MSSQLBatch)

	endOfSectionToMatch := startOfUnicode + len(bytesToMatch)
	sectionToMatch := make([]byte, len(bytesToMatch))
	copy(bytes[startOfUnicode : endOfSectionToMatch], sectionToMatch[:])

	return Compare(bytesToMatch, sectionToMatch) == 0
}

func (t *MSSQLToxic) Pipe(stub *ToxicStub) {
	for {
		select {
		case <-stub.Interrupt:
			return
		case c := <-stub.Input:
			if c == nil {
				stub.Close()
				return
			}

		}
	}
}

func init() {
	Register("mssql", new(MSSQLToxic))
}
