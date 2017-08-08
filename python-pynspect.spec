%global pypi_name pynspect
%global pypi_version 0.5

%if 0%{?el6}
%global python3_pkgversion 33
%global py3_build CFLAGS="-O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fexceptions --param=ssp-buffer-size=4 -mtune=generic" python3 setup.py build
%endif

%if x%{?python3_pkgversion} == x
%global python3_pkgversion 3
%endif

Name:           python-%{pypi_name}
Version:        %{pypi_version}
Release:        0%{?dist}
Summary:        Python 3 library for filtering, querying or inspecting almost arbitrary data structures

License:        MIT
URL:            https://homeproj.cesnet.cz/git/mentat-ng.git
Source0:        https://files.pythonhosted.org/packages/source/p/%{pypi_name}/%{pypi_name}-%{version}.tar.gz
BuildArch:      noarch
 
%description
Python library for filtering, querying or inspecting almost arbitrary data
structures.This README file is work in progress, for more information please
consult source code and unit tests.

%package -n     python2-%{pypi_name}
Summary:        %{summary}
%{?python_provide:%python_provide python2-%{pypi_name}}
Requires:	python2-ipranges
Requires:	python2-typedcols
Requires:	python2-idea-format
Requires:	python2-ply
BuildRequires:	python2-devel
BuildRequires:	python-nose
BuildRequires:	python-setuptools
BuildRequires:	python-idea-format
BuildRequires:	python-ply

%description -n python2-%{pypi_name}
Python library for filtering, querying or inspecting almost arbitrary data
structures.This README file is work in progress, for more information please
consult source code and unit tests.

%package -n     python%{python3_pkgversion}-%{pypi_name}
Summary:        %{summary}
%{?python_provide:%python_provide python%{python3_pkgversion}-%{pypi_name}}

Requires:       python%{python3_pkgversion}-ipranges
Requires:	python%{python3_pkgversion}-typedcols
Requires:	python%{python3_pkgversion}-idea-format
Requires:	python%{python3_pkgversion}-ply
BuildRequires:	python%{python3_pkgversion}-devel
BuildRequires:	python%{python3_pkgversion}-nose
BuildRequires:	python%{python3_pkgversion}-setuptools
BuildRequires:	python%{python3_pkgversion}-idea-format
BuildRequires:	python%{python3_pkgversion}-ply


%description -n python%{python3_pkgversion}-%{pypi_name}
Python 3 library for filtering, querying or inspecting almost arbitrary data
structures.This README file is work in progress, for more information please
consult source code and unit tests.


%prep
%setup -n %{pypi_name}-%{version}
# Remove bundled egg-info
rm -rf %{pypi_name}.egg-info

%build
%py2_build
%py3_build

%install
# Must do the subpackages' install first because the scripts in /usr/bin are
# overwritten with every setup.py install.
%{__python3} setup.py install --skip-build --single-version-externally-managed --root %{buildroot}
%{__python2} setup.py install --skip-build --single-version-externally-managed --root %{buildroot}


%check
%{__python2} setup.py test
%{__python3} setup.py test

%files -n python2-%{pypi_name}
%doc README.rst
%{python_sitelib}

%files -n python%{python3_pkgversion}-%{pypi_name}
%doc README.rst
%{python3_sitelib}

