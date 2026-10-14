package system.log

import rego.v1

# Local demonstration only. Erase each raw field AND its derived normalized
# coordinate; retaining a derived value would disclose the same evidence.
mask contains "/input/profile" if input.input.mask_profile
mask contains "/input/record/profile" if input.input.mask_profile
mask contains "/input/first_times" if input.input.mask_times
mask contains "/input/record/ranks" if input.input.mask_times
