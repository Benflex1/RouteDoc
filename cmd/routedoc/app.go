package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"routedoc/internal/clientprobe"
	"routedoc/internal/model"
	"routedoc/internal/render"
	"routedoc/internal/schema/v1"
)

const (
	ExitOK       = 0
	ExitBlocked  = 1
	ExitData     = 2
	ExitUsage    = 3
	ExitInternal = 4
)

type App struct {
	Args     []string
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	ReadFile func(string) ([]byte, error)
	Diagnose func(context.Context, string, model.Producer) (model.ValidatedEvaluatedRun, error)
}

func NewApp(args []string, in io.Reader, out, err io.Writer, read func(string) ([]byte, error)) *App {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = io.Discard
	}
	if err == nil {
		err = io.Discard
	}
	if read == nil {
		read = os.ReadFile
	}
	return &App{Args: args, Stdin: in, Stdout: out, Stderr: err, ReadFile: read, Diagnose: clientprobe.Diagnose}
}
func (a *App) Run() int {
	if len(a.Args) == 0 {
		return a.usage("a command is required")
	}
	switch a.Args[0] {
	case "render":
		return a.render()
	case "explain":
		return a.explain()
	case "validate":
		return a.validate()
	case "version":
		return a.version()
	default:
		return a.probe()
	}
}
func (a *App) usage(msg string) int {
	fmt.Fprintln(a.Stderr, msg)
	fmt.Fprintln(a.Stderr, "usage: routedoc render REPORT.json [--verbose] [--json]")
	fmt.Fprintln(a.Stderr, "       routedoc explain REPORT.json FINDING_ID [--json]")
	fmt.Fprintln(a.Stderr, "       routedoc validate REPORT.json [--json]")
	fmt.Fprintln(a.Stderr, "       routedoc version [--json]")
	fmt.Fprintln(a.Stderr, "       routedoc URL [--verbose] [--json]")
	return ExitUsage
}

func (a *App) probe() int {
	rawURL, verbose, jsonOut, ok := parseProbeArgs(a.Args)
	if !ok {
		return a.usage("invalid URL arguments")
	}
	if a.Diagnose == nil {
		return a.internalOutput()
	}
	v, err := a.Diagnose(context.Background(), rawURL, model.Producer{Name: ProducerName, Version: ProducerVersion, Build: ProducerBuild})
	if err != nil {
		var input *clientprobe.InputError
		if errors.As(err, &input) {
			fmt.Fprintln(a.Stderr, input.Code)
			return ExitUsage
		}
		return a.internalOutput()
	}
	if jsonOut {
		b, issues := v1.EncodeCanonical(v)
		if len(issues) > 0 {
			return a.internalOutput()
		}
		if _, err := a.Stdout.Write(b); err != nil {
			return ExitInternal
		}
	} else if err := render.Report(a.Stdout, v, render.Options{Verbose: verbose}); err != nil {
		return ExitInternal
	}
	switch clientprobe.Status(v) {
	case clientprobe.StatusSatisfied:
		return ExitOK
	case clientprobe.StatusBlocked:
		return ExitBlocked
	default:
		return ExitData
	}
}

func (a *App) internalOutput() int {
	fmt.Fprintln(a.Stderr, "internal_error")
	return ExitInternal
}
func (a *App) read(path string, op v1.Operation) (v1.DecodedReport, model.ValidatedEvaluatedRun, model.ValidationIssues, int) {
	if path == "-" {
		return v1.DecodedReport{}, model.ValidatedEvaluatedRun{}, model.ValidationIssues{{Code: model.CodeInvalidValue, Pointer: "/args/1", Message: "stdin is not an implicit report source"}}, ExitUsage
	}
	data, err := a.ReadFile(path)
	if err != nil {
		return v1.DecodedReport{}, model.ValidatedEvaluatedRun{}, model.ValidationIssues{{Code: model.CodeInvalidValue, Pointer: "/report", Message: err.Error()}}, ExitData
	}
	d, issues := v1.Decode(data, op)
	if len(issues) > 0 {
		return d, model.ValidatedEvaluatedRun{}, issues, ExitData
	}
	valid, issues := model.ValidatePersistedEvaluatedRun(d.Run)
	if len(issues) > 0 {
		return d, valid, issues, ExitData
	}
	return d, valid, nil, ExitOK
}
func (a *App) render() int {
	path, verbose, jsonOut, ok := parseRenderArgs(a.Args[1:])
	if !ok {
		return a.usage("invalid render arguments")
	}
	d, v, issues, code := a.read(path, v1.ReadRender)
	if len(issues) > 0 {
		printIssues(a.Stderr, issues)
		return code
	}
	if jsonOut {
		if !d.Exact {
			printIssues(a.Stderr, model.ValidationIssues{{Code: model.CodeExactVersionRequired, Pointer: "/report_schema_version", Message: "render JSON requires exact version"}})
			return ExitData
		}
		b, issues := v1.EncodeCanonical(v)
		if len(issues) > 0 {
			printIssues(a.Stderr, issues)
			return ExitInternal
		}
		_, err := a.Stdout.Write(b)
		if err != nil {
			return ExitInternal
		}
		return ExitOK
	}
	printWarnings(a.Stderr, d.Warnings)
	if err := render.Report(a.Stdout, v, render.Options{Verbose: verbose}); err != nil {
		fmt.Fprintln(a.Stderr, err)
		return ExitInternal
	}
	return ExitOK
}
func (a *App) explain() int {
	path, id, jsonOut, ok := parseExplainArgs(a.Args[1:])
	if !ok {
		return a.usage("invalid explain arguments")
	}
	d, v, issues, code := a.read(path, v1.ReadExplain)
	if len(issues) > 0 {
		printIssues(a.Stderr, issues)
		return code
	}
	printWarnings(a.Stderr, d.Warnings)
	fid, err := model.ParseFindingID(id)
	if err != nil {
		return a.usage("invalid finding ID")
	}
	e, err := render.BuildExplanation(v, fid)
	if err != nil {
		fmt.Fprintln(a.Stderr, err)
		return ExitData
	}
	if jsonOut {
		if err := writeExplanationJSON(a.Stdout, e); err != nil {
			return ExitInternal
		}
		return ExitOK
	}
	if err := render.Explain(a.Stdout, v, fid, render.Options{}); err != nil {
		return ExitInternal
	}
	return ExitOK
}
func (a *App) validate() int {
	path, jsonOut, ok := parseValidateArgs(a.Args[1:])
	if !ok {
		return a.usage("invalid validate arguments")
	}
	data, err := a.ReadFile(path)
	if err != nil {
		issues := model.ValidationIssues{{Code: model.CodeInvalidValue, Pointer: "/report", Message: err.Error()}}
		if jsonOut {
			writeValidationJSON(a.Stdout, false, issues, nil)
		} else {
			printIssues(a.Stderr, issues)
		}
		return ExitData
	}
	d, decodeIssues := v1.Decode(data, v1.ReadValidate)
	if len(decodeIssues) > 0 {
		if jsonOut {
			writeValidationJSON(a.Stdout, false, decodeIssues, nil)
		} else {
			printIssues(a.Stderr, decodeIssues)
		}
		return ExitData
	}
	_, issues := model.ValidatePersistedEvaluatedRun(d.Run)
	if jsonOut {
		if err := writeValidationJSON(a.Stdout, len(issues) == 0, issues, d.Warnings); err != nil {
			return ExitInternal
		}
	} else {
		printWarnings(a.Stderr, d.Warnings)
		if len(issues) > 0 {
			printIssues(a.Stderr, issues)
		} else {
			fmt.Fprintln(a.Stdout, "valid")
		}
	}
	if len(issues) > 0 {
		return ExitData
	}
	return ExitOK
}
func (a *App) version() int {
	if len(a.Args) != 1 && !(len(a.Args) == 2 && a.Args[1] == "--json") {
		return a.usage("invalid version arguments")
	}
	if len(a.Args) == 2 {
		if err := writeVersionJSON(a.Stdout); err != nil {
			return ExitInternal
		}
		return ExitOK
	}
	fmt.Fprintf(a.Stdout, "routedoc %s (build %s)\n", ProducerVersion, ProducerBuild)
	return ExitOK
}
