## Borrowed bytes shared by the TLS layers. The networking buffer module has
## no runtime dependency. Aliases and inline procedures generate plain pointers.
import zal_net/buffers
export BytesPtr

type Bytes* = BytesPtr

proc at*(p: Bytes; i: int): Bytes {.inline.} = offset(p, i)

proc ptrOf*[I](a: var array[I, byte]): Bytes {.inline.} = arrayBytes(a)

proc bytesOf*(s: var seq[byte]): Bytes {.inline.} =
  ## Empty storage is valid only for a zero-length operation.
  bytesPtr(dataPtr(s))

proc textBytes*(s: var string): Bytes {.inline.} =
  ## Read-only borrow. Nimony's toCString requires var; keep the string alive
  ## and unchanged while using the pointer, including across passive calls.
  result = cast[Bytes](s.toCString)
