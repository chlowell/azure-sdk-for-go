package internal

import (
	"sync"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
)

func TestThing(t *testing.T) {
	c := NewCache(func(cae bool) (cache.ExportReplace, error) {
		return nil, nil
	})
	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			ExportReplace(c, true)
			wg.Done()
		}()
	}
}