unset EXPLODED
declare -a EXPLODED
function explode 
{
	local c=$# 
	(( c < 2 )) && 
	{
		echo function "$0" is missing parameters 
		return 1
	}

	local delimiter="$1"
	local string="$2"
	local limit=${3-99}

	local tmp_delim=$'\x07'
	local delin=${string//$delimiter/$tmp_delim}
	local oldifs="$IFS"

	IFS="$tmp_delim"
	EXPLODED=($delin)
	IFS="$oldifs"
}

