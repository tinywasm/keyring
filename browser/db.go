//go:build wasm

package browser

import (
	"syscall/js"

	_ "github.com/tinywasm/await"
	"github.com/tinywasm/keyring"
)

const (
	dbName    = "tinywasm-keyring"
	dbVersion = 1
	storeKEK  = "kek"
	storeSec  = "secrets"
)

var cachedDB js.Value

func openDB() (js.Value, error) {
	if cachedDB.Truthy() {
		return cachedDB, nil
	}

	idb := js.Global().Get("indexedDB")
	req := idb.Call("open", dbName, dbVersion)

	onUpgrade := js.FuncOf(func(this js.Value, args []js.Value) any {
		e := args[0]
		db := e.Get("target").Get("result")

		if !db.Get("objectStoreNames").Call("contains", storeKEK).Bool() {
			opts := jsObject.New()
			opts.Set("keyPath", "id")
			db.Call("createObjectStore", storeKEK, opts)
		}
		if !db.Get("objectStoreNames").Call("contains", storeSec).Bool() {
			opts := jsObject.New()
			opts.Set("keyPath", "id")
			db.Call("createObjectStore", storeSec, opts)
		}
		return nil
	})
	defer onUpgrade.Release()
	req.Set("onupgradeneeded", onUpgrade)

	db, err := awaitRequest(req)
	if err != nil {
		return js.Undefined(), keyring.Wrap("keyring/browser: openDB", err)
	}
	cachedDB = db
	return db, nil
}

type SecretRecord struct {
	id   string
	iv   []byte
	data []byte
}

func getSecretRecord(id string) (*SecretRecord, error) {
	db, err := openDB()
	if err != nil {
		return nil, err
	}

	tx := db.Call("transaction", storeSec, "readonly")
	store := tx.Call("objectStore", storeSec)
	req := store.Call("get", id)

	res, err := awaitRequest(req)
	if err != nil || !res.Truthy() {
		return nil, keyring.ErrNotFound
	}

	iv := arrayBufferToSlice(res.Get("iv"))
	data := arrayBufferToSlice(res.Get("data"))
	return &SecretRecord{id: id, iv: iv, data: data}, nil
}

func putSecretRecord(id string, iv []byte, data []byte) error {
	db, err := openDB()
	if err != nil {
		return err
	}

	tx := db.Call("transaction", storeSec, "readwrite")
	store := tx.Call("objectStore", storeSec)

	rec := jsObject.New()
	rec.Set("id", id)
	rec.Set("iv", sliceToUint8Array(iv).Get("buffer"))
	rec.Set("data", sliceToUint8Array(data).Get("buffer"))

	req := store.Call("put", rec)
	_, err = awaitRequest(req)
	return err
}

func deleteSecretRecord(id string) error {
	db, err := openDB()
	if err != nil {
		return err
	}

	rec, err := getSecretRecord(id)
	if err != nil {
		return keyring.ErrNotFound
	}
	_ = rec

	tx := db.Call("transaction", storeSec, "readwrite")
	store := tx.Call("objectStore", storeSec)
	req := store.Call("delete", id)
	_, err = awaitRequest(req)
	return err
}

func deleteServiceSecrets(service string) error {
	db, err := openDB()
	if err != nil {
		return err
	}

	tx := db.Call("transaction", storeSec, "readwrite")
	store := tx.Call("objectStore", storeSec)
	req := store.Call("openCursor")

	prefix := service + "\x00"

	for {
		cursorRes, err := awaitRequest(req)
		if err != nil || !cursorRes.Truthy() {
			break
		}
		cursor := cursorRes
		key := cursor.Get("key").String()

		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delReq := cursor.Call("delete")
			_, _ = awaitRequest(delReq)
		}

		contReq := cursor.Call("continue")
		_, err = awaitRequest(contReq)
		if err != nil {
			break
		}
	}

	return nil
}

type KEKRecord struct {
	ID         string
	Key        js.Value
	WrappedDEK []byte
	HKDFSalt   []byte
}

func getKEKRecord(id string) (*KEKRecord, error) {
	db, err := openDB()
	if err != nil {
		return nil, err
	}

	tx := db.Call("transaction", storeKEK, "readonly")
	store := tx.Call("objectStore", storeKEK)
	req := store.Call("get", id)

	res, err := awaitRequest(req)
	if err != nil || !res.Truthy() {
		return nil, keyring.ErrNotFound
	}

	key := res.Get("key")
	wrappedDEK := arrayBufferToSlice(res.Get("wrappedDEK"))
	var hkdfSalt []byte
	if res.Get("hkdfSalt").Truthy() {
		hkdfSalt = arrayBufferToSlice(res.Get("hkdfSalt"))
	}
	return &KEKRecord{ID: id, Key: key, WrappedDEK: wrappedDEK, HKDFSalt: hkdfSalt}, nil
}

func putKEKRecord(id string, key js.Value, wrappedDEK []byte) error {
	return putKEKRecordWithSalt(id, key, wrappedDEK, nil)
}

func putKEKRecordWithSalt(id string, key js.Value, wrappedDEK []byte, hkdfSalt []byte) error {
	db, err := openDB()
	if err != nil {
		return err
	}

	tx := db.Call("transaction", storeKEK, "readwrite")
	store := tx.Call("objectStore", storeKEK)

	rec := jsObject.New()
	rec.Set("id", id)
	if key.Truthy() {
		rec.Set("key", key)
	}
	rec.Set("wrappedDEK", sliceToUint8Array(wrappedDEK).Get("buffer"))
	if len(hkdfSalt) > 0 {
		rec.Set("hkdfSalt", sliceToUint8Array(hkdfSalt).Get("buffer"))
	}

	req := store.Call("put", rec)
	_, err = awaitRequest(req)
	return err
}
