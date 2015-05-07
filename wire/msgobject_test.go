package wire_test

import (
	"testing"

	"github.com/monetas/bmutil/wire"
)

func TestObjectTypeString(t *testing.T) {
	// check if unknowns are handled properly
	str := wire.ObjectType(4).String()
	if str != "Unknown" {
		t.Errorf("expected Unknown got %s", str)
	}
	str = wire.ObjectType(985621).String()
	if str != "Unknown" {
		t.Errorf("expected Unknown got %s", str)
	}

	// check existing object types
	for i := wire.ObjectType(0); i < wire.ObjectType(4); i++ {
		str = i.String()
		if str == "Unknown" {
			t.Errorf("did not expect Unknown for %d", i)
		}
	}
}
