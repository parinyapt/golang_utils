package PTGUtimezone

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
)

func GlobalTimezoneSetup(tz string) error {
	if tz == "" {
		return errors.New("[Info][PTGUtimezone][TimezoneSetup()]->Timezone Config is empty, using default timezone")
	}

	loc, err := time.LoadLocation(tz) 
	if err != nil {
		return errors.New(fmt.Sprintf("[Error][PTGUtimezone][TimezoneSetup()]->Failed to LoadLocation Timezone Config : %s", err))
	}
	time.Local = loc // -> this is setting the global timezone
	return nil
	// https://stackoverflow.com/questions/54363451/setting-timezone-globally-in-golang
}