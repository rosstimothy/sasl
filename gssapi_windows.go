// +build windows

package sasl

import (
	"errors"
	"syscall"
	"unsafe"

	"github.com/alexbrainman/sspi"
)

type context struct {
	creds            *sspi.Credentials
	spn              string
	Handle           sspi.CtxtHandle
	EstablishedFlags uint32
	RequestedFlags   uint32
	expiry           syscall.Filetime
}

func (c *context) Sizes() (*sspi.SecPkgContext_Sizes, syscall.Errno) {
	var s sspi.SecPkgContext_Sizes
	ret := sspi.QueryContextAttributes(&c.Handle, sspi.SECPKG_ATTR_SIZES, (*byte)(unsafe.Pointer(&s)))
	if ret != sspi.SEC_E_OK {
		return nil, ret
	}
	return &s, ret
}

func gssapi(spn string) Mechanism {
	return Mechanism{
		Name: "GSSAPI",
		Start: func(m *Negotiator) (bool, []byte, interface{}, error) {

			ctx := context{RequestedFlags: sspi.ISC_REQ_MUTUAL_AUTH |
				sspi.ISC_REQ_ALLOCATE_MEMORY |
				sspi.ISC_REQ_CONFIDENTIALITY |
				sspi.ISC_REQ_REPLAY_DETECT}
			creds, err := sspi.AcquireCredentials("", sspi.MICROSOFT_KERBEROS_NAME, sspi.SECPKG_CRED_BOTH, nil)
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

				if ret != sspi.SEC_E_OK {
					return false, nil, nil, errors.New("failed to initialize security context")
				}

				tokenB := token[0].Bytes()
				challenge := make([]byte, len(tokenB))
				copy(challenge, tokenB)

				return true, challenge, ctx, nil
			case ResponseSent:
				var token [2]sspi.SecBuffer
				token[0].Set(sspi.SECBUFFER_STREAM, challenge)
				token[1].Set(sspi.SECBUFFER_DATA, []byte{})

				var qop uint32
				ret := sspi.DecryptMessage(&ctx.Handle, sspi.NewSecBufferDesc(token[:]), 0, &qop)
				if ret != sspi.SEC_E_OK {
					return false, nil, nil, errors.New("failed to verify response")
				}

				tokenB := token[1].Bytes()
				if len(tokenB) != 4 {
					return false, nil, nil, errors.New("negotiation failed")
				}

				sizes, ret := ctx.Sizes()
				if ret != sspi.SEC_E_OK {
					return false, nil, nil, errors.New("context size information unavailable")
				}

				var response [3]sspi.SecBuffer
				response[0].Set(sspi.SECBUFFER_TOKEN, make([]byte, sizes.SecurityTrailer))
				//TODO: use established security layer
				response[1].Set(sspi.SECBUFFER_DATA, []byte{1, 0, 0, 0}) //token)
				response[2].Set(sspi.SECBUFFER_PADDING, make([]byte, sizes.BlockSize))

				ret = sspi.EncryptMessage(&ctx.Handle, 0, sspi.NewSecBufferDesc(response[:]), 0)
				if ret != sspi.SEC_E_OK {
					return false, nil, nil, errors.New("message encryption failed")
				}

				d0 := response[0].Bytes()
				d1 := response[1].Bytes()
				d2 := response[2].Bytes()

				challenge := make([]byte, len(d0)+len(d1)+len(d2))
				copy(challenge, d0)
				copy(challenge[len(d0):], d1)
				copy(challenge[len(d1):], d2)

				return true, challenge, ctx, nil
			case ValidServerResponse:
				return false, nil, nil, nil
			}
			return
		},
	}
}
