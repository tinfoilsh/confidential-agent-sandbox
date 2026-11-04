package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
)

const (
	ownerCommandName = "workspace-owner"
	instancePath     = "/run/workspace/instance"
	ownerStatus      = "status"
	ownerEnroll      = "enroll"
)

func runOwnerCommand(args []string, input io.Reader, output io.Writer) error {
	if len(args) != 1 || (args[0] != ownerStatus && args[0] != ownerEnroll) {
		return errors.New("usage: workspace-owner status | enroll < input.json")
	}
	if os.Geteuid() != 0 {
		return errors.New("run workspace-owner with sudo")
	}
	instance, err := os.ReadFile(instancePath)
	if err != nil {
		return err
	}
	work, err := newWorkspace(string(instance))
	if err != nil {
		return err
	}
	return work.command(context.Background(), args[0], input, output)
}

func (w *workspace) command(ctx context.Context, operation string, input io.Reader, output io.Writer) error {
	var result status
	var err error
	switch operation {
	case ownerStatus:
		result, err = w.status(ctx)
	case ownerEnroll:
		body, readErr := io.ReadAll(io.LimitReader(input, maxOwnerBytes+1))
		defer clear(body)
		if readErr != nil {
			return readErr
		}
		var in enrollInput
		if len(body) > maxOwnerBytes || json.Unmarshal(body, &in) != nil {
			return errMalformed
		}
		result, err = w.enroll(ctx, in)
	default:
		return errMalformed
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}
