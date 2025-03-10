package certs

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

const (
	// MtlsImplantCA - Directory containing HTTPS server certificates
	MtlsImplantCA = "mtls-implant"
	MtlsServerCA  = "mtls-server"
)

// MtlsC2ServerGenerateECCCertificate - Generate a server certificate signed with a given CA
func MtlsC2ServerGenerateRSACertificate(host string) ([]byte, []byte, error) {
	cert, key := GenerateRSACertificate(MtlsServerCA, host, false, false)
	err := saveCertificate(MtlsServerCA, RSAKey, host, cert, key)
	return cert, key, err
}

// MtlsC2ImplantGenerateRSACertificate - Generate a server certificate signed with a given CA
func MtlsC2ImplantGenerateECCCertificate(name string) ([]byte, []byte, error) {
	cert, key := GenerateRSACertificate(MtlsImplantCA, name, false, true)
	err := saveCertificate(MtlsImplantCA, RSAKey, name, cert, key)
	return cert, key, err
}
