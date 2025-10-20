# Define Go-related macros
%global goipath         github.com/lotke/check_ssl_cert
%global commit          abc1234567890abcdef1234567890abcdef1234
%global shortcommit     %(c=%{commit}; echo ${c:0:7})
                                                    
Name:           check_ssl_cert 
Version:        1.0.4                
Release:        1%{?dist}          
Summary:        Icinga check for HTTPS certificate validity
                                                    
License:        MIT                                                                                      
URL:            https://github.com/lotke/check_ssl_cert                                            
Source0: https://github.com/lotke/check_ssl_cert/archive/refs/tags/%{version}.tar.gz
# Build requirements for Go                                                                              
BuildRequires:  golang >= 1.18
BuildRequires:  git
BuildRequires:  go-rpm-macros
BuildRequires:  gcc 
BuildRequires:  rpm-build                                                                                
BuildRequires:  redhat-rpm-config
                                                    
# Runtime dependencies                                                                                   
Requires:       glibc
                                                    
# Enable Go module support   
%gometa              

%description
check_ssl_cert is a command-line tool for checking the validity of HTTPS
certificates, designed for use with Icinga monitoring. It verifies certificate
expiration and supports custom DNS servers, configurable timeouts, and older
SSL/TLS versions.

%prep                                                                                                                                                                                                      [0/9968]
%autosetup -n %{name}-%{version}                                                                         

# Create go.mod if it doesn't exist in the source tarball
if [ ! -f go.mod ]; then
    cat > go.mod << 'EOF'
module github.com/lotke/check_ssl_cert

go 1.18

require github.com/dustin/go-humanize v1.0.1
EOF
fi

# Generate or update go.sum to include dependency checksums
go mod tidy

%build
# Set up Go environment explicitly, using absolute paths
mkdir -p $RPM_BUILD_DIR/go
mkdir -p $RPM_BUILD_DIR/go/cache
export GOPATH=$RPM_BUILD_DIR/go
export GOCACHE=$RPM_BUILD_DIR/go/cache
export SOURCE_DATE_EPOCH=1760572800

# Build the Go binary with Fedora-specific flags
go build -buildmode pie -compiler gc -tags=rpm_crashtraceback -a -v \
  -ldflags "-B 0x6db323e624b7e9e12ac5e897f3166db5910ca699 -compressdwarf=false -linkmode=external \
  -extldflags '-Wl,-z,relro -Wl,--as-needed -Wl,-z,pack-relative-relocs -Wl,-z,now \
  -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 \
  -Wl,--build-id=sha1 -specs=/usr/lib/rpm/redhat/redhat-package-notes'" \
  -o bin/%{name} %{goipath}

%install
# Install the binary
install -Dpm 0755 bin/%{name} %{buildroot}%{_bindir}/%{name}

# Install the license file
install -Dpm 0644 LICENSE %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

%check
# Run Go tests (if any exist)
go test -v %{goipath}

%files
%{_bindir}/%{name}
%license %{_datadir}/licenses/%{name}/LICENSE
%doc README.md


%changelog
* Thu Oct 16 2025 Your Name <your.email@example.com> - 1.0.0-1
- Initial package release
