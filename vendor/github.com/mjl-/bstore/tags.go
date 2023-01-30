package bstore

import (
	"fmt"
	"strings"
)

type storeTags []string

func newStoreTags(tag string, isPK bool) (storeTags, error) {
	if tag == "" {
		return nil, nil
	}

	l := strings.Split(tag, ",")
	for _, s := range l {
		w := strings.SplitN(s, " ", 2)
		switch w[0] {
		case "noauto", "typename":
			if !isPK {
				return nil, fmt.Errorf("%w: cannot have tag %q for non-primary key", ErrType, w[0])
			}
		case "index", "unique", "default", "-":
			if isPK {
				return nil, fmt.Errorf("%w: cannot have tag %q on primary key", ErrType, w[0])
			}
		case "name", "nonzero", "ref":
		default:
			return nil, fmt.Errorf("%w: unknown store tag %q", ErrType, w[0])
		}
	}
	return storeTags(l), nil
}

func (t storeTags) Has(word string) bool {
	for _, s := range t {
		if s == word {
			return true
		}
	}
	return false
}

func (t storeTags) Get(word string) (string, error) {
	wordsp := word + " "
	for _, s := range t {
		if strings.HasPrefix(s, wordsp) {
			r := s[len(wordsp):]
			if r == "" {
				return "", fmt.Errorf("%w: bstore word %q requires non-empty parameter", ErrType, word)
			}
			return r, nil
		} else if s == word {
			return "", fmt.Errorf("%w: bstore word %q requires argument", ErrType, word)
		}
	}
	return "", nil
}

func (t storeTags) List(word string) []string {
	var l []string
	wordsp := word + " "
	for _, s := range t {
		if strings.HasPrefix(s, wordsp) {
			l = append(l, s[len(wordsp):])
		}
	}
	return l
}
