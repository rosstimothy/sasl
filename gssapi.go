// +build !windows

package sasl

import (
	"errors"
	"sync"
	"time"

	gss "github.com/apcera/gssapi"
	"github.com/sirupsen/logrus"
)

type context struct {
	lib   *gss.Lib
	cred  *gss.CredId
	ctx   *gss.CtxId
	name  *gss.Name
	flags uint32
}

var loadOnce sync.Once

func loadLib() (lib *gss.Lib, err error) {
	loadOnce.Do(func() {
		logrus.Info("loading gssapi")

		gsslib, er := gss.Load(nil)
		if er != nil {
			err = er
			logrus.WithError(err).Error("failed to load gssapi")
		}

		lib = gsslib
		return
	})
	return
}

func gssapi(spn string) Mechanism {
	return Mechanism{
		Name: "GSSAPI",
		Start: func(m *Negotiator) (bool, []byte, interface{}, error) {

			lib, err := loadLib()
			if err != nil {
				return false, nil, nil, err
			}

			nameBuf, err := lib.MakeBufferString(spn)
			if err != nil {
				logrus.Error(err.Error())
				return false, nil, nil, errors.New("unable to initialize security context")
			}
			defer nameBuf.Release()

			name, err := nameBuf.Name(lib.GSS_KRB5_NT_PRINCIPAL_NAME)
			if err != nil {
				return false, nil, nil, errors.New("unable to initialize security context")
			}

			ctx := &context{
				cred:  lib.GSS_C_NO_CREDENTIAL,
				name:  name,
				ctx:   nil,
				lib:   lib,
				flags: gss.GSS_C_MUTUAL_FLAG | gss.GSS_C_REPLAY_FLAG | gss.GSS_C_CONF_FLAG,
			}

			var outgoingToken *gss.Buffer
			ctx.ctx, _, outgoingToken, _, _, err = ctx.lib.InitSecContext(
				ctx.cred,
				ctx.ctx,
				ctx.name,
				ctx.lib.GSS_C_NO_OID,
				ctx.flags,
				time.Duration(0),
				ctx.lib.GSS_C_NO_CHANNEL_BINDINGS,
				ctx.lib.GSS_C_NO_BUFFER)
			defer outgoingToken.Release()

			if err != gss.ErrContinueNeeded {
				logrus.Error(err.Error())
				return false, nil, nil, errors.New("failed to initialize security context")
			}

			tokenB := outgoingToken.Bytes()
			challenge := make([]byte, len(tokenB))
			copy(challenge, tokenB)

			return true, challenge, ctx, nil
		},
		Next: func(m *Negotiator, challenge []byte, data interface{}) (more bool, resp []byte, cache interface{}, err error) {
			if challenge == nil {
				return false, nil, nil, ErrInvalidChallenge
			}

			ctx, ok := data.(*context)
			if !ok {
				return false, nil, nil, errors.New("invalid context")
			}
			defer func() {
				if err != nil {
					ctx.ctx.Release()
				}
			}()

			state := m.State()

			switch state & StepMask {
			case AuthTextSent:
				incomingTokenBuffer, err := ctx.lib.MakeBufferBytes(challenge)
				if err != nil {
					return false, nil, nil, errors.New("unable to initialize security context")
				}
				defer incomingTokenBuffer.Release()
				var outgoingToken *gss.Buffer
				ctx.ctx, _, outgoingToken, _, _, err = ctx.lib.InitSecContext(
					ctx.cred,
					ctx.ctx,
					ctx.name,
					ctx.lib.GSS_C_NO_OID,
					ctx.flags,
					time.Duration(0),
					ctx.lib.GSS_C_NO_CHANNEL_BINDINGS,
					incomingTokenBuffer)
				defer outgoingToken.Release()

				if err != nil {
					logrus.Error(err.Error())
					return false, nil, nil, errors.New("failed to initialize security context")
				}

				tokenB := outgoingToken.Bytes()
				challenge := make([]byte, len(tokenB))
				copy(challenge, tokenB)

				return true, challenge, ctx, nil
			case ResponseSent:
				challengeBuf, err := ctx.lib.MakeBufferBytes(challenge)
				if err != nil {
					logrus.Error(err.Error())
					return false, nil, nil, errors.New("unable to unwrwap message")
				}
				defer challengeBuf.Release()

				unwrapped, _, _, err := ctx.ctx.Unwrap(challengeBuf)
				if err != nil {
					logrus.Error(err.Error())
					return false, nil, nil, errors.New("failed to unwrap message")
				}
				defer unwrapped.Release()

				buf, err := ctx.lib.MakeBufferBytes([]byte{1, 0, 0, 0})
				if err != nil {
					logrus.Error(err.Error())
					return false, nil, nil, errors.New("unable to wrap message")
				}
				defer buf.Release()

				_, wrapped, err := ctx.ctx.Wrap(false, 0, buf)
				if err != nil {
					logrus.Error(err.Error())
					return false, nil, nil, errors.New("failed to wrap message")
				}
				defer wrapped.Release()

				wrappedB := wrapped.Bytes()
				challenge := make([]byte, len(wrappedB))
				copy(challenge, wrappedB)

				return true, challenge, ctx, nil
			case ValidServerResponse:
				return false, nil, nil, nil
			}
			return
		},
	}
}
