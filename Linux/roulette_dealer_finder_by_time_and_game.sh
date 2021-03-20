## Dealer Finder by time and game
#$1 is date in four digit monthday format, ex: 0324 is March 24
#$2 is time in 00:00:00 AM/PM, must be input as 00:00:00[[:space:]]AM or 00:00:00[[:space:]]PM
#$3 is the game. 
#       input 1 for Blackjack
#       input 2 for Roulette
#       input 3 for Texas Hold Em



#!/bin/bash

if [ $3 = "1" ]; then
  grep -i $2 $1_Dealer_schedule | awk -F" " '{print $1, $2, $3, $4}'
elif [ $3 = "2" ]; then
  grep -i $2 $1_Dealer_schedule | awk -F" " '{print $1, $2, $5, $6}'
elif [ $3 = "3" ]; then
  grep -i $2 $1_Dealer_schedule | awk -F" " '{print $1, $2, $7, $8}'
fi