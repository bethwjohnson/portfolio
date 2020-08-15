## Roulette dealer finder by time
#$1 is date in four digit monthday format. EX: 0324 for March 24
#$2 is time in 00:00:00 AM/PM format. Formatting is critical - see note below:
#NOTE:  MUST input argument in this format: 00:00:00[[:space:]]AM or 00:00:00[[:space:]]PM

#! bin/bash

grep -i $2 $1_Dealer_schedule | awk -F" " '{print $1, $2, $5, $6}'