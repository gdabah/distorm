shopt -s expand_aliases
alias get_array_by_ref='e="$( declare -p ${1} )"; eval "declare -A E=${e#*=}"'
alias get_indexed_array_by_ref='e="$( declare -p ${1} )"; eval "declare -a E=${e#*=}"'

setifs() {
	local newifs=${1-$'\x20\x09\x0a'}
	IFS=$newifs
}

# Example of usage:
# explode "e-" "apple-pie-kandy"
# declare -p EXPLODED


pop() {
	local stacklen=${#_GLOBAL_STACK[*]}
	local _={$stacklen:?POP_EMPTY_GLOBAL_STACK}
	(( stacklen = (stacklen>0) ? -- stacklen : 0 ))
	# echo -en pop "$1 ${_GLOBAL_STACK[$stacklen]}\n"
	# declare -p _GLOBAL_STACK
	local "$1" && upvar "$1" "${_GLOBAL_STACK[$stacklen]}"
	unset _GLOBAL_STACK[$stacklen]
	return $stacklen
}

declare -a _IFS_STACK=()
declare -a _GLOBAL_STACK=()
pushifs() {
	_IFS_STACK[${#_IFS_STACK[*]}]=$IFS		# push the current IFS into the stack
	[ $# -gt 0 ] && IFS=${1}						# set IFS from argument (if there is one)
	# [ $# -gt 0 ] # && echo set IFS || echo didnt set ifs
}

popifs() {
	local stacklen=${#_IFS_STACK[*]}
	local _={$stacklen:?POP_EMPTY_IFS_STACK}
	(( stacklen -- ))
	IFS=${_IFS_STACK[$stacklen]}
	# echo popped IFS, $stacklen remain in stack
}

# $1 variable name to push
push() {
	_GLOBAL_STACK[${#_GLOBAL_STACK[*]}]=${1}		# push var to stack
	# echo -en push "$1\n"
	# declare -p _GLOBAL_STACK
	return $stacklen
}



EXPLODED=
implode() {
	local c=$#
	(( c < 2 )) && 
	{
		echo implode missing $(( 2 - $# )) parameters
		return 1
	}

	# couldn't find a way to pass it properly, so we're doing the same declare trick, but it's done inside the function.
	# def="$( declare -p $2 )"
	# eval "declare -a func_assoc_array="${def#*=}
	# declare -p func_assoc_array

	# Copying an array.
	#array2=( "${array1[@]}" )
	# or
	# array2="${array1[@]}"

	local implode_with="$1"
	shift
	IMPLODED=

	while [ $# -gt 0 ]; do
		IMPLODED+=$1
		shift
		[ $# -gt 0 ] && IMPLODED+=$implode_with
	done
}

# declare -a EXPLODED
_explode() {	# included form explode.inc.sh
	local c=$# 
	(( c < 2 )) && 
	{
		echo explode missing parameters 
		return 1
	}
	local delimiter="$1"
	local string="$2"
	local limit=${3-99}

	local delimiter_len=${#delimiter}
	local tmp_delim=$'\x07'
	local delin=${string//$delimiter/$tmp_delim}
	pushifs $'\x07'
	EXPLODED=($delin)
	popifs
	return 0
}

array_copy() {
	[ $# -lt 2 ] && echo copy missing $# parameters && return 1
	# pushifs $'\x07'
	# eval "$2"="$1"

	local dest=$1
	shift

	eval "$dest=()"
	local ctr=0
	while [ $# -gt 0 ]; do
		eval "$dest[$ctr]=\"$1\""
		(( ctr ++ ))
		shift
	done
}

# usage: in_array needle "${ARRAY[@]}"
in_array() {
	needle="$1"
	shift

	while [ $# -gt 0 ]; do
		if [ "$needle" == "$1" ]; then
			return 0
		fi
		shift
	done
	return 1
}

array_find() {
	needle="$1"
	shift

	local i
	(( i = 0 ))
	while [ $# -gt 0 ]; do
		if [ "$needle" == "$1" ]; then
			return $i
		fi
		(( ++i ))
		shift
	done
	return -1 
}

array_copy_declare() {
	[ $# -lt 2 ] && echo copy_declare missing $# parameters && return 1
	# pushifs $'\x07'
	# eval "$2"="$1"

	local dest=$1
	# shift

	pushifs
	setifs

	local index; eval index=\"\${!$2[*]}\" 				# gives us a copy of the array index   		declare -- a="0 1 2 3 4"
	index=( $index )												# turn it into an array
	# local first; eval first=\"${!2}\"						# gives us the first value in the array -- actualy, value [0]... which isn't a lot of good once we unset it
	# local first; eval first=\"\${$2[@]:0:1}\"

	// local "$1" && upvar $1 "${EXPLODED[@]}"
	local -a __array
	for key in ${index[@]}; do
		__array[$key]=
	done


	# couldn't find a way to pass it properly, so we're doing the same declare trick, but it's done inside the function.
	local array_name
	local _type
	local _definition
	local _declare
	array_name="$2"
	def="$( declare -p "$array_name" )"
	read _declare _type _definition < <( echo "$def" )
	_type=${_type:1:1}		# A)ssociate  a)rray  -)var  f)function ?
	# see http://stackoverflow.com/questions/4069188/how-to-pass-an-associative-array-as-argument-to-a-function-in-bash
	# echo eval "local -A func_assoc_array="${json_command#*=}

	local de="${def#*=}"
	eval echo "declare -${_type} func_assoc_array=$de"
	eval "declare -${_type} func_assoc_array=$de"
	declare -p func_assoc_array
	sleep 1
	# declare -A func_assoc_array='([0]="'\''([operation]=\"push\" [stackname]=\"ba\\\"sh ^B: ^A: ^C: ^? ^H ^I^@:\" )'\''" )'
	# exit
	local key
	local value
	local e_key
	local e_value
	local json_pair
	local json
	local keys
	local ignore_keys=0

	keys=${!func_assoc_array[@]}

	# If it is a non-associative array, or the first key is 0, assume we can ignore keys in JSON output
	if [ "$_type" == "a" -o "${keys[0]}" == "0" ]; then
		ignore_keys=1
	fi

	
	popifs

	COPY= 
	local ctr=0
	while [ $# -gt 0 ]; do
		eval "$dest[$ctr]=\"$1\""
		(( ctr ++ ))
		shift
	done
}


print_r() {
	declare -p EXPLODED
}
	
# Test
# explode "," "1,\"2\",3,, b ,4,5"
# echo -n print_r: 
# print_r EXPLODED
# # e=("${EXPLODED[*]}")
# array_copy COPY "${EXPLODED[@]}"
# declare -p COPY
# implode "-" "${COPY[@]}"
# declare -p IMPLODED
# 
# clear

test_crap_x() {

EXPLODED=( "1" '"2"' "3" "" " b " "4,5" 6 )
__a=$( declare -p EXPLODED )
# echo implode "-" "${EXPLODED[@]}"
implode "-" "${EXPLODED[@]}"
# declare -p IMPLODED
explode "-" "$IMPLODED"
__b=$( declare -p EXPLODED )
if [ "$__a" != "$__b" ]; then
	echo implode/explode test error > /dev/stderr
	exit 1
fi

}

array_keys() {
	if (( $# < 2 )); then
		echo "Usage: array_keys stuff "
		return 1
	fi

	local index; 
	eval index=\"\${!$2[*]}\" 		# gives us a copy of the array index   		declare -- a="0 1 2 3 4"
	eval 'index="${!'"$2"'[*]}"'
	index=( $index )
	echo $index
}

_pop() {
	local stacklen=${#_GLOBAL_STACK[*]}
	local _={$stacklen:?POP_EMPTY_GLOBAL_STACK}
	(( stacklen = (stacklen>0) ? -- stacklen : 0 ))
	# echo -en pop "$1 ${_GLOBAL_STACK[$stacklen]}\n"
	# declare -p _GLOBAL_STACK
	local "$1" && upvar "$1" "${_GLOBAL_STACK[$stacklen]}"
	unset _GLOBAL_STACK[$stacklen]
	return $stacklen
}
array_get() {
	if (( $# < 3 )); then
		echo "Usage: array_get DESTVAR ARRAY INDEX"
		return 1
	fi
	local -i i=$3

	local val; eval val=\$\{$2\[$i\]\}
	local "$1" && upvar $1 "$val"
}

array_pop() {
	if (( $# < 2 )); then
		echo "Usage: array_pop DESTVAR ARRAYVAR"
		return 1
	fi

	# Method x.  Anything but method 1, please.
	local stacklen; eval stacklen=\$\{#$2\[\*\]\}
	# local _={$stacklen:?POP_EMPTY_GLOBAL_STACK}
	(( stacklen = (stacklen>0) ? -- stacklen : 0 ))
	# echo -en pop "$1 ${_GLOBAL_STACK[$stacklen]}\n"
	# declare -p _GLOBAL_STACK
	# local "$1" && upvar "$1" "${_GLOBAL_STACK[$stacklen]}"
	eval last=\$\{$2\[$stacklen\]\}
	local "$1" && upvar "$1" "${_GLOBAL_STACK[$stacklen]}"
	unset $2[$stacklen]
	# unset _GLOBAL_STACK[$stacklen]
	local "$1" && upvar $1 "$last"
	return $stacklen

	# Method 1.  The nastiest.
	pushifs
	setifs

	local index; eval index=\"\${!$2[*]}\" 		# gives us a copy of the array index   		declare -- a="0 1 2 3 4"
	index=( $index )
	local count=${#index[@]}
	# (( count -- ))
	local last_key=${index[$(( count - 1 ))]}
	# echo -n last_key: $last_key which is " "
	# local last; eval last=\"\${$2[@]:$count:1}\"
	local last; eval last=\"\${$2[\$last_key]}\"
	# echo $last
	
	popifs
	if [ -z "$index" ]; then
		# No elements in array
		return 1
	fi
	# ../bash/array_shift.inc.sh: line 23: unset: __funcname: not an array variable
	# echo unsettings index "'$index'"
	unset -v "$2[$last_key]" 

	# if [ "${#first}" -ne "${#${first//$'\x03'}}" ]; then
		explode $'\x02' "$last"
	# fi
	local "$1" && upvar $1 "${EXPLODED[@]}"
}


array_swap() {
	if (( $# < 3 )); then
		echo "Usage: array_swap ARRAY INDEX1 INDEX2"
		return 1
	fi
	local a=$1
	local -i bill=$2
	local -i bob=$3
	local temp;
	# Oh so bad and unchecked and exploitable
	eval temp=\$\{$a\[$bill\]\}
	eval $a\[$bill\]=\$\{$a\[$bob\]\}
	eval $a\[$bob\]=\$temp
}


Countries=(Netherlands Ukraine Zaire Turkey Russia Yemen Syria \
Brazil Argentina Nicaragua Japan Mexico Venezuela Greece England \
Israel Peru Canada Oman Denmark Wales France Kenya \
Xanadu Qatar Liechtenstein Hungary)

array_sort() {
	if (( $# < 1 )); then
		echo "Usage: array_sort ARRAY"
		return 1
	fi

	local stacklen; eval stacklen=\$\{#$1\[\*\]\}

	# echo "0: ${Countries[*]}"  # List entire array at pass 0.
	# number_of_elements=${#Countries[@]}

	(( comparisons = stacklen - 1 ))
	(( count = 1 ))
	while (( comparisons > 0 ))
	do
		index=0  # Reset index to start of array after each pass.
		while [ "$index" -lt "$comparisons" ] # Beginning of inner loop
		do
			if [ ${Countries[$index]} \> ${Countries[`expr $index + 1`]} ]
				#  If out of order...
				#  Recalling that \> is ASCII comparison operator
				#+ within single brackets.

				#  if [[ ${Countries[$index]} > ${Countries[`expr $index + 1`]} ]]
				#+ also works.
			then
				exchange $index `expr $index + 1`  # Swap.
			fi  
			let "index += 1"
		done # End of inner loop

# ----------------------------------------------------------------------
# Paulo Marcel Coelho Aragao suggests for-loops as a simpler altenative.
#
# for (( last = $number_of_elements - 1 ; last > 1 ; last-- ))
# do
#     for (( i = 0 ; i < last ; i++ ))
#     do
#         [[ "${Countries[$i]}" > "${Countries[$((i+1))]}" ]] \
#             && exchange $i $((i+1))
#     done
# done
# ----------------------------------------------------------------------
  

		let "comparisons -= 1" #  Since "heaviest" element bubbles to bottom,
		#+ we need do one less comparison each pass.

		echo
		echo "$count: ${Countries[@]}"  # Print resultant array at end of each pass.
		echo
		let "count += 1"                # Increment pass count.

	done                            # End of outer loop
	# All done.

}
##### BUB

# array_shift <array_var_name> into <var_name>
function array_shift_into
{

	(( $# > 1 )) && if [[ $2 != "into" ]]
	then
		echo "Invalid arguments passed to $FUNCNAME: $@" >&2
		return 1
	fi

	local __array_var_name=$1
	local __var_name=$3

	local __first=
	local __rest=

	e="$( declare -p "$__array_var_name" )"; 
	e=${e#*=}
	e=${e#\'}
	e=${e%\'}
	eval "declare E=$e"
	(( ${#E[@]} < 1 )) && return 1
	set -- "${E[@]}"
	# echo "Positional parameters are 1:$1 2:$2 3:$3 4:$4 etc..."
	test -n "$__var_name" && local "$__var_name" && upvar $__var_name "$1"
	shift
	A=( "$@" )
	eval $__array_var_name='("${A[@]}")'
	# local "$__array_var_name" && upvar $__array_var_name "$@"
	# upvar didn't work so well when the array got down to a single member (tried to set it to a flat variable)

	#	
	#   # alias get_array_by_ref='e="$( declare -p ${1} )"; eval "declare -A E=${e#*=}"'
	#   # KEYS=( "${!E[@]}" )
}

array_shift() {
	if (( $# < 2 )); then
		echo "Usage: array_shift DESTVAR ARRAYVAR"
		return 1
	fi

	# Method 1.  The nastiest.
	pushifs
	setifs

	local index; eval index=\"\${!$2[*]}\" 		# gives us a copy of the array index   		declare -- a="0 1 2 3 4"
	index=( $index )
	# local first; eval first=\"${!2}\"						# gives us the first value in the array -- actualy, value [0]... which isn't a lot of good once we unset it
	local first; eval first=\"\${$2[@]:0:1}\"
	
	popifs
	if [ -z "$index" ]; then
		# No elements in array
		return 1
	fi
	# ../bash/array_shift.inc.sh: line 23: unset: __funcname: not an array variable
	# echo unsettings index "'$index'"
	unset -v "$2[$index]" 

	# if [ "${#first}" -ne "${#${first//$'\x03'}}" ]; then
		explode $'\x02' "$first"
	# fi
	local "$1" && upvar $1 "${EXPLODED[@]}"
}

array_push() {
	if (( $# < 2 )); then
		echo "Usage: array_push ARRAY VAR [ VAR [ VAR ... ]]"
		return 1
	fi
	
	# Method x.  The one I just came up with.
	eval $1+=\(\$2\)
	return

	# Method 1.  The nastiest.
	local a
	a=$1; shift
	if (( $# > 0 )); then
		# eval "$a+=\(\\\"$*\\\"\)"									# it works, and *appears* to be save for dangerous values of $2 
		
		# XXX:dangerous?, $a could do damage if it's a space? 
		# eval $a+='('$*')'
		eval $a=\(\"\${@}\"\)  											# from 'upvar'
	fi
			


	# echo "${a[0]}"
}

in_array_1() {
	NEEDLE="$1"

	pushifs
	setifs


	# index=(${!TEST[@]})
	local index; eval index=\"\${!$2[*]}\" 		# gives us a copy of the array index   		declare -- a="0 1 2 3 4"
	index=( $index )
	# local first; eval first=\"${!2}\"						# gives us the first value in the array -- actualy, value [0]... which isn't a lot of good once we unset it
	local first; eval first=\"\${$2[@]:0:1}\"
	
	popifs
	if [ -z "$index" ]; then
		# No elements in array
		return 1
	fi
}

array_count() {
	local count; eval count=\"\${#$1[@]}\"
	return $count
}

#
# lets try:
# array_chunk <chunksize> "array" "as" "parameters"
array_chunk() {
	local chunksize="$1"
	set - 

	# bah

}

test_crap_2() {
	newarray=( an array )
	array=( pinky went to porky town )
	array[5]="and bought a"
	array+=( '"pig"' )


	echo "${array[@]}"
	# pinky went to porky town and bought a pig
	array_count array; count=$?; echo $count elements in array

	array_shift pigname array
	array_count array; count=$?; echo $count elements in array

	array_push array "sausage"
	array_count array; count=$?; echo $count elements in array

	echo the pigs name was $pigname
	echo and he bought a "${array[@]}"

	# the pigs name was pinky
	# and he went to porky town and bought a sausage


	declare -p array

	array_push newarray "start"
	declare -p newarray
	array_push newarray "one"
	declare -p newarray
	array_push newarray '"two"'
	declare -p newarray
	array_push newarray 'three "4" five' 6 seven
	declare -p newarray
	array_push newarray "three" 4 "five" 
	declare -p newarray

	array_pop word newarray && declare -p word
	declare -p newarray
	array_pop word newarray && declare -p word
	declare -p newarray
	array_pop word newarray && declare -p word
	declare -p newarray
	array_pop word newarray && declare -p word
	declare -p newarray
	array_pop word newarray && declare -p word
	declare -p newarray
	array_pop word newarray && declare -p word
	declare -p newarray
	array_pop word newarray && declare -p word
	declare -p newarray
	array_pop word newarray && declare -p word
	declare -p newarray
	array_pop word newarray && declare -p word
	declare -p newarray
	array_pop word newarray && declare -p word
	declare -p newarray
}


