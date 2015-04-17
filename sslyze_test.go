package sslyze

import (
	"fmt"
	"io/ioutil"
	"testing"
)

func TestParse(t *testing.T) {
	data, err := ioutil.ReadFile("sslyze2.xml")
	if err != nil {
		t.Error(err)
	}

	r, err := Parse(data)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("%#v\n", r)
}
