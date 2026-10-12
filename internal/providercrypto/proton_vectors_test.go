package providercrypto_test

// Fixed synthetic vectors generated independently by pre-existing GnuPG 2.4.7
// (libgcrypt 1.11.0), not by providercrypto or its Go cryptography libraries.
// Generation profile: AES256, iterated/salted SHA256 S2K count65011712,
// MDC, binary literal, empty filename, with none/ZLIB/ZIP compression.
const protonVectorPassword = "  synthetic-🔐-password  "
const protonVectorPlaintext = "{\"version\":\"1.42.0\",\"vaults\":{},\"synthetic\":\"  exact\\r\\n🔐  \"}\x00\r\n"

var protonIndependentVectors = []struct{ name, armored string }{
	{"none", `-----BEGIN PGP MESSAGE-----

jA0ECQMIt9XOxDBmC2j/0nQBR+csyaDupy3X86edbjCAEhMaQvbBE68NJm5yt5dI
AG8PaXGE9jrJWwhpT8dpah46VKGqsSVWpk4fCp2+g85OJdDgv2UtnDFKnd5uMUoz
7KpJ/GyXu9ClzWQ41pasKmSCesKLoeMvXwxcAsQV+1C51sJLgA==
=TbJC
-----END PGP MESSAGE-----
`},
	{"zlib", `-----BEGIN PGP MESSAGE-----

jA0ECQMIY6Y7JXwt3gX/0n4BSarcuUj1FtO1OxRwllY/zGXJT8vJ6sPax8iaKYdd
A08olwvEK7fXHeWqHnzoVTHywYbVpcovG94+qWCLj5whkfLWJdw+2FvIH0PByxUo
Egw5/ii0w43mcQLGo8Zl3PI05n4fBohMQJH2ubCIS+CGD9fpbdx+HqzTxSQ0Lew=
=pAgk
-----END PGP MESSAGE-----
`},
	{"zip", `-----BEGIN PGP MESSAGE-----

jA0ECQMIsqX243kK6Oz/0ngBfmoJBmzqito2I5AvgohpNfLZF19CMJSBjuOKpkM9
V+7vx2BMWEnsa0UqEKwgw2hWz/dwNoLHruE5uSA9+0JsyjRoYfewpiCsmPjaP6BV
DHLR3X1xKP2iLt7OEJ7BOUMRwvrbPJwyZfuVecbX4iELxx3cYXU6O4U=
=YcEu
-----END PGP MESSAGE-----
`},
}
