// Copyright 2018 Thales UK Limited
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
package erfserver

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	erf "github.com/thales-e-security/erfcommon"
)

/*

Graph for testing. '?' is a subject that we've only seen as a 'prev' link.
Update using http://asciiflow.com.

Format is ERF(ops performed, ID, time)

+------------------------------------------------------------------------------+
|                                                                              |
|                                                                              |
|                                                            +->K(1,A,1)       |
|                                                            |                 |
|                                 +-->C(1,A,1)+----->D(2,A,1)|                 |
|                                 |                          |                 |
|                                 |                          +->E(1,E,2)       |
|                                 |                                            |
|           A(2,A,1)+---->B(3,A,1)|                                            |
|                                 |                                            |
|                                 |                                            |
|                                 +-->F(1,F,2)+----->G(1,F,2)+-->L(1,F,2)      |
|                                                            |                 |
|                                                            |                 |
|                                                            |                 |
|                                                            +-->M(1,M,3)      |
|                                                                              |
|                                                                              |
|                                                                              |
|                                                                              |
|  ? +---> H(1,?,1)                                                            |
|                                                                              |
|                                                                              |
|                                                                              |
|          J(1,J,1)+----> I(1,J,1)                                             |
|                                                                              |
|                                                                              |
+------------------------------------------------------------------------------+

From above graph:
  Client | Operations
     A        9
     E        1
     F        3
     M        1
     ?        1
     J        2


*/

var time1 = time.Now()
var time2 = time1.Add(time.Second)
var time3 = time2.Add(time.Second)

func populateServer(t *testing.T) ERFServer {
	server := NewInMemory()

	// 2 operations for [A]
	server.Append(makeJWT(t, "", "A"), "op", time1)
	server.Append(makeJWT(t, "", "A"), "op", time1)

	// 3 operations for [B]
	server.Append(makeJWT(t, "A", "B"), "op", time1)
	server.Append(makeJWT(t, "A", "B"), "op", time1)
	server.Append(makeJWT(t, "A", "B"), "op", time1)

	server.Append(makeJWT(t, "B", "C"), "op", time1)

	// 2 operations for [D]
	server.Append(makeJWT(t, "C", "D"), "op", time1)
	server.Append(makeJWT(t, "C", "D"), "op", time1)

	server.Append(makeJWT(t, "D", "K"), "op", time1)
	server.Append(makeJWT(t, "D", "E"), "op", time2)

	server.Append(makeJWT(t, "B", "F"), "op", time2)
	server.Append(makeJWT(t, "F", "G"), "op", time2)
	server.Append(makeJWT(t, "G", "L"), "op", time2)
	server.Append(makeJWT(t, "G", "M"), "op", time3)
	server.Append(makeJWT(t, "?", "H"), "op", time1)
	server.Append(makeJWT(t, "", "J"), "op", time1)
	server.Append(makeJWT(t, "J", "I"), "op", time1)

	return server
}

func TestCountingClients(t *testing.T) {
	server := populateServer(t)
	assert.Equal(t, 6, server.TotalClients())
}

func TestCountingClientsSince(t *testing.T) {
	server := populateServer(t)
	assert.Equal(t, 3, server.RecentClients(time2))
}

func TestCountOperations(t *testing.T) {
	server := populateServer(t)

	res := server.OperationsByClient()

	expected := make(map[string]int)
	expected["A"] = 9
	expected["E"] = 1
	expected["F"] = 3
	expected["M"] = 1
	expected["?"] = 1
	expected["J"] = 2

	for k, v := range expected {
		assert.Equal(t, v, res[k]["op"])
	}
}

func makeJWT(t *testing.T, prev, subj string) []byte {
	claims := erf.ErfClaims{
		Subject:    erf.StringPtr(subj),
		Previous:   erf.StringPtr(prev),
		SequenceNo: erf.Int64Ptr(0), // don't currently base any logic on this
		IssuedAt:   erf.Int64Ptr(time.Now().Unix()),
		ExpiresAt:  erf.Int64Ptr(time.Now().Add(20 * time.Second).Unix()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodNone, &claims)
	s, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return []byte(s)
}
