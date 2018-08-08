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
	"sync"
	"time"

	"github.com/pkg/errors"
	erf "github.com/thales-e-security/erfcommon"
)

// ERFServer registers client operations and indicates the number of unique
// clients in use.
type ERFServer interface {
	// Append adds an operation to a log
	Append(token []byte, operation string, time time.Time) error

	// TotalClients returns the number of distinct clients seen
	TotalClients() int

	// RecentClients returns the number of clients with operations recorded after (or equal) to since
	RecentClients(since time.Time) int

	// OperationsByClient returns a map of canonical client IDs, with a sub-map with a count of operations.
	OperationsByClient() map[string]map[string]int
}

// adjacencyListPair holds the incoming and outgoing adjacency lists for the graph.
type adjacencyListPair struct {
	incoming map[string]*stringSet
	outgoing map[string]*stringSet
}

// record captures the data for a single operation.
type record struct {
	// subject is the ERF at the time of the operation.
	subject string

	// previous is the previous ERF (or "" if the ERF hasn't rolled over yet).
	previous string

	// operation is a string description of the operation the client performed.
	operation string

	// utcTime is the time the operation was received by the server.
	utcTime int64
}

// NewInMemory creates an ERFServer that stores records in a simple in-memory array.
func NewInMemory() ERFServer {
	return &inMemoryERFServer{}
}

type inMemoryERFServer struct {
	// store as simple array, to reflect future blockchain implementation
	records []record

	// mux protects the array of records
	mux sync.Mutex
}

// OperationsByClient implements ERFServer.OperationsByClient
func (s *inMemoryERFServer) OperationsByClient() map[string]map[string]int {
	s.mux.Lock()
	defer s.mux.Unlock()

	lists := s.adjacencyLists(nil)
	result := make(map[string]map[string]int)

	canonicalIDs := mapCanonicalIDs(lists)

	for _, record := range s.records {
		clientID := canonicalIDs[record.subject]
		clientOperations, found := result[clientID]
		if !found {
			clientOperations = make(map[string]int)
			result[clientID] = clientOperations
		}

		clientOperations[record.operation]++
	}

	return result
}

// mapCanonicalIDs parses the DAG and maps every ERF to a canonical client ID. Each
// time the tree has a branch, a new canonical client ID is generated for the new branch. The result is a mapping
// from ERF->canonicalID.
func mapCanonicalIDs(lists adjacencyListPair) map[string]string {
	result := make(map[string]string)

	for node, incomingEdges := range lists.incoming {
		// If a root node...
		if incomingEdges == nil {
			var nodes stringStack
			var ids stringStack

			ids.push(node)

			for n := &node; n != nil; n = nodes.pop() {
				id := ids.pop()

				// store mapping from ERF to ID
				result[*n] = *id

				if lists.outgoing[*n] != nil {
					for x, child := range lists.outgoing[*n].values() {
						if x == 0 {
							ids.push(*id)
						} else {
							ids.push(child)
						}
						nodes.push(child)
					}
				}
			}
		}
	}

	return result
}

// RecentClients implements ERFServer.RecentClients
func (s *inMemoryERFServer) RecentClients(since time.Time) int {
	s.mux.Lock()
	defer s.mux.Unlock()
	return countSinks(s.adjacencyLists(&since).outgoing)
}

// TotalClients implements ERFServer.TotalClients
func (s *inMemoryERFServer) TotalClients() int {
	s.mux.Lock()
	defer s.mux.Unlock()
	return countSinks(s.adjacencyLists(nil).outgoing)
}

// countSinks finds leaf nodes, or 'sinks' in the DAG. Each sink represents a
// distinct client.
func countSinks(outgoingAdjacencyList map[string]*stringSet) int {
	sinks := 0

	// Find sinks in graph
	for _, value := range outgoingAdjacencyList {
		if value == nil {
			sinks++
		}
	}
	return sinks
}

// adjacencyLists builds a pair of adjacency lists (one incoming, one outgoing). The ordering of the
// edges is consistent over time, due to the use of stringSet internally. It assumes s.mux is held by the
// caller.
func (s *inMemoryERFServer) adjacencyLists(since *time.Time) adjacencyListPair {
	res := adjacencyListPair{
		incoming: make(map[string]*stringSet),
		outgoing: make(map[string]*stringSet),
	}

	var sinceUTC int64

	if since != nil {
		sinceUTC = since.UTC().Unix()
	}

	for _, record := range s.records {
		if since != nil && record.utcTime < sinceUTC {
			continue
		}

		sub := record.subject
		pre := record.previous

		// Always record the existence of a subject, in case it's a orphaned leaf.
		// The code below preserves the existing value at that key.
		res.incoming[sub] = res.incoming[sub]
		res.outgoing[sub] = res.outgoing[sub]

		// If there was a previous subject, add an edge to point to this subject
		if pre != "" {
			if res.outgoing[pre] == nil {
				res.outgoing[pre] = newStringSet()
			}
			res.outgoing[pre].add(sub)

			if res.incoming[sub] == nil {
				res.incoming[sub] = newStringSet()
			}
			res.incoming[sub].add(pre)

			// we should also ensure there is a record of this previous node, in case we didn't
			// receive a record about it
			res.incoming[pre] = res.incoming[pre]
		}
	}

	return res
}

// Append implements ERFServer.Append
func (s *inMemoryERFServer) Append(token []byte, operation string, time time.Time) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	// Check token is valid before we store it
	_, claims, err := erf.ParseToken(token)
	if err != nil {
		return errors.Wrap(err, "failed to read token")
	}

	s.records = append(s.records, record{
		subject:   *claims.Subject,
		previous:  *claims.Previous,
		operation: operation,
		utcTime:   time.UTC().Unix(),
	})
	return nil
}
