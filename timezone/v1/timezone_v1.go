package PTGUtimezone

import (
	"log"
	"time"
)

func GlobalTimezoneSetup(tz string) {
	loc, err := time.LoadLocation(tz) 
	if err != nil {
		log.Fatalf("[Error][PTGUtimezone][TimezoneSetup()]->Failed to LoadLocation Timezone Config : %s", err)
	}
	time.Local = loc // -> this is setting the global timezone
	// https://stackoverflow.com/questions/54363451/setting-timezone-globally-in-golang
}