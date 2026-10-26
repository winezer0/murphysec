package toolver

import (
	"context"
	"reflect"
)

var Default Config
var postprocessors []func(context.Context, *Config)

type mavenCommandOverrideKey struct{}

func WithMavenCommandOverride(ctx context.Context, command string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, mavenCommandOverrideKey{}, command)
}

func Get(ctx context.Context) *Config {
	var r = mergeConfig(mergeConfig(&Default, getIntellijConfig()), getFromEnv())
	for _, it := range postprocessors {
		it(ctx, r)
	}
	if ctx != nil {
		if command, ok := ctx.Value(mavenCommandOverrideKey{}).(string); ok {
			r.Maven.MavenCommand = command
		}
	}
	return r
}

func mergeConfig(old *Config, new *Config) *Config {
	if old == nil && new == nil {
		return nil
	}
	if old == nil {
		c := *new
		return &c
	}
	if new == nil {
		c := *old
		return &c
	}

	result := *old

	mergeStruct(reflect.ValueOf(&result).Elem(), reflect.ValueOf(new).Elem())

	return &result
}

func mergeStruct(dst, src reflect.Value) {
	for i := 0; i < dst.NumField(); i++ {
		dstField := dst.Field(i)
		srcField := src.Field(i)

		if !srcField.IsValid() || !srcField.CanInterface() {
			continue
		}

		switch dstField.Kind() {
		case reflect.Struct:
			mergeStruct(dstField, srcField)
		default:
			if !srcField.IsZero() {
				if dstField.CanSet() {
					dstField.Set(srcField)
				}
			}
		}
	}
}
