// +build windows

package sasl

import (
	"errors"
	"syscall"

	"github.com/alexbrainman/sspi"
)

func ntlm(spn string) Mechanism {
	return Mechanism{
		Name: "GSS-SPGENO",
		Start: func(m *Negotiator) (bool, []byte, interface{}, error) {

			ctx := context{RequestedFlags: sspi.ISC_REQ_MUTUAL_AUTH |
				sspi.ISC_REQ_ALLOCATE_MEMORY} // |
			// sspi.ISC_REQ_CONFIDENTIALITY |
			// sspi.ISC_REQ_REPLAY_DETECT}
			creds, err := sspi.AcquireCredentials("", sspi.NTLMSP_NAME, sspi.SECPKG_CRED_BOTH, nil)
			if err != nil {
				return false, nil, nil, errors.New("failed to acquire credentials")
			}

			ctx.creds = creds
			defer func() {
				if err != nil {
					sspi.FreeCredentialsHandle(&ctx.creds.Handle)
					sspi.DeleteSecurityContext(&ctx.Handle)
				}
			}()

			target, err := syscall.UTF16PtrFromString(spn)
			if err != nil {
				return false, nil, nil, errors.New("faild to get spn")
			}

			token := []sspi.SecBuffer{
				{BufferType: sspi.SECBUFFER_TOKEN},
			}
			defer func() {
				token[0].Free()
			}()

			ret := sspi.InitializeSecurityContext(&ctx.creds.Handle, nil, target, ctx.RequestedFlags,
				0, sspi.SECURITY_NATIVE_DREP, nil, 0, &ctx.Handle, sspi.NewSecBufferDesc(token),
				&ctx.EstablishedFlags, &ctx.expiry)

			if ret != sspi.SEC_I_CONTINUE_NEEDED {
				return false, nil, nil, errors.New("failed to initialize security context")
			}

			tokenB := token[0].Bytes()
			challenge := make([]byte, len(tokenB))
			copy(challenge, tokenB)

			return true, challenge, ctx, nil
		},
		Next: func(m *Negotiator, challenge []byte, data interface{}) (more bool, resp []byte, cache interface{}, err error) {
			if challenge == nil {
				return false, nil, nil, ErrInvalidChallenge
			}

			ctx, ok := data.(context)
			if !ok {
				return false, nil, nil, errors.New("invalid context")
			}
			defer func() {
				if err != nil {
					sspi.FreeCredentialsHandle(&ctx.creds.Handle)
					sspi.DeleteSecurityContext(&ctx.Handle)
				}
			}()

			state := m.State()

			switch state & StepMask {
			case AuthTextSent:
				inBuff := []sspi.SecBuffer{
					{BufferType: sspi.SECBUFFER_TOKEN},
					{BufferType: sspi.SECBUFFER_EMPTY},
				}

				inBuff[0].Set(sspi.SECBUFFER_TOKEN, challenge)

				token := []sspi.SecBuffer{
					{BufferType: sspi.SECBUFFER_TOKEN},
				}
				defer func() {
					token[0].Free()
				}()

				target, err := syscall.UTF16PtrFromString(spn)
				if err != nil {
					return false, nil, nil, errors.New("faild to get spn")
				}

				ret := sspi.InitializeSecurityContext(&ctx.creds.Handle, &ctx.Handle, target, ctx.RequestedFlags,
					0, sspi.SECURITY_NATIVE_DREP, sspi.NewSecBufferDesc(inBuff), 0, &ctx.Handle, sspi.NewSecBufferDesc(token),
					&ctx.EstablishedFlags, &ctx.expiry)

				tokenB := token[0].Bytes()
				challenge := make([]byte, len(tokenB))
				copy(challenge, tokenB)

				switch ret {
				case sspi.SEC_E_OK:
					if len(challenge) > 0 {
						return true, challenge, ctx, nil
					}
					return false, challenge, ctx, nil
				case sspi.SEC_I_COMPLETE_NEEDED, sspi.SEC_I_COMPLETE_AND_CONTINUE:
					ret = sspi.CompleteAuthToken(&ctx.Handle, sspi.NewSecBufferDesc(token))
					if ret != sspi.SEC_E_OK {
						return true, challenge, ctx, errors.New("failed to complete authentication")
					}
					return true, challenge, ctx, nil
				case sspi.SEC_I_CONTINUE_NEEDED:
				default:
					return true, challenge, ctx, nil
				}
			case ResponseSent:
				return false, nil, nil, nil
			case ValidServerResponse:
				return false, nil, nil, nil
			}
			return
		},
	}
}
