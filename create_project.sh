#!/bin/bash

set -e

_prefix="medusa2"

if [[ -z "${1}" ]]; then
	echo "Usage:" >/dev/stderr
	echo "  ${0} <project_name>" >/dev/stderr
	echo "<project_name> shall not contain the prefix '${_prefix}'" >/dev/stderr
	exit 1
fi

_canon_name="$(echo "${1}" | sed -r "s,/+$,,;s,\\W,-,g")"
_full_name="${_prefix}-${_canon_name}"

if [[ -d "${_full_name}" ]]; then
	echo "Project directory already exists:" >/dev/stderr
	echo "  ${_full_name}" >/dev/stderr
	echo "You have to remove it before proceeding." >/dev/stderr
	exit 1
fi

echo "Creating empty project in directory '${_full_name}'..."
cp -RpT "${_prefix}-@@temp-late@@" "${_full_name}"
sed -i -r -e "s,@@temp(-|_)late@@,$(echo "${_canon_name}" | sed -r "s,-,\\\\1,g;s,\\w,\\l&,g"),g"	\
          -e "s,@@Temp(-|_)late@@,$(echo "${_canon_name}" | sed -r "s,-,\\\\1,g;s,\\<\\w,\\u&,g"),g"	\
          -e "s,@@TEMP(-|_)LATE@@,$(echo "${_canon_name}" | sed -r "s,-,\\\\1,g;s,\\w,\\u&,g"),g"	\
	$(find "${_full_name}" -type f)
ln -sf "./" "${_full_name}/${_full_name}"
ln -sf "../etc/" "${_full_name}/etc"

echo "Creating configure files..."
touch "etc/${_prefix}/${_full_name}-template.conf"
ln -sf "${_full_name}-template.conf" "etc/${_prefix}/${_full_name}.conf"

echo "Registering NEW project in 'configure.ac' and 'Makefile.am'..."
sed -i -r -z "s,\\]\\)\\n##_INSERT_NEW_MAKEFILE_HERE,\\n\\t${_full_name}/Makefile&," configure.ac
sed -i -r -z "s,\\n##_INSERT_NEW_CONFIG_FILE_HERE,\\t\\\\\\n\\tetc/${_prefix}/${_full_name}-template.conf&," Makefile.am
sed -i -r -z "s,\\n##_INSERT_NEW_DIRECTORY_HERE,\\t\\\\\\n\\t${_full_name}&," Makefile.am

echo "Registering NEW library in 'main.conf'..."
sed -i -r -z "s,\\n##_INSERT_NEW_MODULE_HERE,\\ninit_module = lib${_full_name}.so&," "$(readlink -f "etc/${_prefix}/main.conf")"

echo "Finished. You have to rerun 'configure' to build the new project."
