package store

import (
	"github.com/mjl-/mox/spf"
)

var spfValidations = map[spf.Status]Validation{
	spf.StatusNone:      ValidationNone,
	spf.StatusNeutral:   ValidationNeutral,
	spf.StatusPass:      ValidationPass,
	spf.StatusFail:      ValidationFail,
	spf.StatusSoftfail:  ValidationSoftfail,
	spf.StatusTemperror: ValidationTemperror,
	spf.StatusPermerror: ValidationPermerror,
}

// SPFValidation returns a Validation for an spf.Status.
func SPFValidation(status spf.Status) Validation {
	v, ok := spfValidations[status]
	if !ok {
		panic("missing spf status validation")
	}
	return v
}
