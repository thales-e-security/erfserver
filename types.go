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

// stringStack is a simple LIFO stack for strings.
type stringStack struct {
	s []string
}

// push pushes a value onto the stack.
func (s *stringStack) push(val string) {
	s.s = append(s.s, val)
}

// pop retrieves a pointer to the last pushed value, or nil if the stack is empty.
func (s *stringStack) pop() *string {
	l := len(s.s)

	if l == 0 {
		return nil
	}

	res := s.s[l-1]
	s.s = s.s[:l-1]
	return &res
}

// stringSet is a collection of unique strings that preserve insertion order. Use newStringSet to construct.
type stringSet struct {
	set  map[string]bool
	keys []string
}

// newStringSet creates an empty stringSet.
func newStringSet() *stringSet {
	return &stringSet{
		set:  make(map[string]bool),
		keys: nil,
	}
}

// add appends val to the string set. If the set already includes val, nothing is done.
func (s *stringSet) add(val string) {
	if s.set == nil {
		s.set = make(map[string]bool)
	}

	if _, exists := s.set[val]; !exists {
		s.set[val] = true
		s.keys = append(s.keys, val)
	}
}

// values returns the unique strings in the order they were inserted.
func (s *stringSet) values() []string {
	res := make([]string, len(s.keys))
	copy(res, s.keys)
	return res
}
