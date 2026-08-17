//go:build wasm

package browser

import (
	"syscall/js"

	_ "github.com/tinywasm/await"
	"github.com/tinywasm/keyring"
)

func awaitPromise(promise js.Value) (js.Value, error) {
	if !promise.Truthy() {
		return js.Undefined(), keyring.ErrUnavailable
	}

	ch := make(chan struct {
		val js.Value
		err error
	}, 1)

	then := js.FuncOf(func(this js.Value, args []js.Value) any {
		var res js.Value
		if len(args) > 0 {
			res = args[0]
		}
		ch <- struct {
			val js.Value
			err error
		}{val: res, err: nil}
		return nil
	})
	defer then.Release()

	catch := js.FuncOf(func(this js.Value, args []js.Value) any {
		ch <- struct {
			val js.Value
			err error
		}{val: js.Undefined(), err: keyring.ErrUnavailable}
		return nil
	})
	defer catch.Release()

	promise.Call("then", then).Call("catch", catch)
	res := <-ch
	return res.val, res.err
}

func awaitRequest(req js.Value) (js.Value, error) {
	if !req.Truthy() {
		return js.Undefined(), keyring.ErrUnavailable
	}

	ch := make(chan struct {
		val js.Value
		err error
	}, 1)

	onsuccess := js.FuncOf(func(this js.Value, args []js.Value) any {
		res := req.Get("result")
		ch <- struct {
			val js.Value
			err error
		}{val: res, err: nil}
		return nil
	})
	defer onsuccess.Release()

	onerror := js.FuncOf(func(this js.Value, args []js.Value) any {
		ch <- struct {
			val js.Value
			err error
		}{val: js.Undefined(), err: keyring.ErrUnavailable}
		return nil
	})
	defer onerror.Release()

	req.Set("onsuccess", onsuccess)
	req.Set("onerror", onerror)

	res := <-ch
	return res.val, res.err
}
