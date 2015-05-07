package json

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/cloudfoundry/cli/cf/errors"
)

func ParseJsonArray(path string) ([]map[string]interface{}, error) {
	if path == "" {
		return nil, nil
	}

	bytes, err := readJsonFile(path)
	if err != nil {
		return nil, err
	}

	stringMaps := []map[string]interface{}{}
	err = json.Unmarshal(bytes, &stringMaps)
	if err != nil {
		return nil, errors.NewWithFmt("Incorrect json format: %s", err.Error())
	}

	return stringMaps, nil
}

func ParseJsonHash(path string) (map[string]interface{}, error) {
	if path == "" {
		return nil, nil
	}

	bytes, err := readJsonFile(path)
	if err != nil {
		return nil, err
	}

	stringMap := map[string]interface{}{}
	err = json.Unmarshal(bytes, &stringMap)
	if err != nil {
		return nil, errors.NewWithFmt("Incorrect json format: %s", err.Error())
	}

	return stringMap, nil
}

func ParseJsonFromFileOrString(fileOrJson string) (map[string]interface{}, error) {
	var jsonMap map[string]interface{}
	var err error

	jsonMap, err = ParseJsonHash(fileOrJson)
	if err != nil {
		jsonMap = make(map[string]interface{})
		err = json.Unmarshal([]byte(fileOrJson), &jsonMap)
		if err != nil && fileOrJson != "" {
			return nil, err
		}
	}
	return jsonMap, nil
}

func readJsonFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}
