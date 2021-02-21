#!/usr/bin/env bash

source bash/upvars.inc.sh 
source bash/explode.inc.sh
source bash/arrays.inc.sh

# sfink@280x linux $ ndisasm.exe -b 64 -o 0x140016124 torture.bin > rn.asm
# sfink@280x linux $ ./disasm.exe -b64 torture.bin 0x140016124 > rd.asm

flags=$( echo {{c,p,a,z,s,t,i,d,o,r,vi}f,ac,id,iopl,nt,vip,vm} )
r8=$(    echo {{{a,c,d,b}{h,l},{s,b}pl,{s,d}il},r{8..15}b}     )
r16=$(   echo {{{a,c,d,b}x,{s,b}p,{s,d}i},r{8..15}w}           )
r32=$(   echo {e{{a,c,d,b}x,{s,b}p,{s,d}i},r{8..15}d}          )
r64=$(   echo r{{a,c,d,b}x,{s,b}p,{s,d}i,{8..15}}              )
xmm=$(   echo xmm{0..15}                                       )
ymm=$(   echo ymm{0..15}                                       )
zmm=$(   echo zmm{0..15}                                       )
ptrd=$(  echo {byte,{,d,q,dq,y}word,tbyte}                     ) # distorm ptr sizes
ptrn=$(  echo {byte,{,d,q,o,y,z}word}                          ) # ndisasm ptr sizes (guessed)
condd=$(   echo j{ae,a,be,b,cxz,ecxz,ge,g,le,l,no,np,ns,nz,o,p,rcxz,s,z} ) # distorm conditionals
condn=$( echo j{nc,a,na,c,ecxz,ecxz,nl,g,ng,l,no,po,ns,nz,o,pe,rcxz,s,z} ) # ndisasm conditionals


# combined distorm and ndisasm ptr sizes
ptr="$ptrd $ptrn"

# all registers
registers=( $r8 $r16 $r64 $xmm $ymm $zmm )

# ordered array of operands to match again ptr sizes
opsna=("$r8" "$r16" "$r32" "$r64" "$xmm" "$ymm" "$zmm")
ptrna=( $ptrn ) # ndisasm
ptrda=( $ptrn ) # distorm (won't need these)
condda=( $condd )
condna=( $condn )


# used to calculate the required ptr size for an immediate value
hexlen() {
    local num=$1
    local v
    (( num )) || return 1
    (( num > 0 )) && {
        v=$(( num ))
    }
    (( num < 0 )) && {
        num=${num#-}
        v=$(( num ));
        (( v-- ))
    }
    local n;
    printf -v n "%x" $v;
    local l=${#n};
    
    # add some extra bits if the MSB is set
    [[ $n =~ ^([89a-f]) ]] && (( l++ ))
    return $l
}
log2() {
    local v=$1
    local -i r=0
    while (( v >>= 1 )); do (( r++ )); done
    return $r
}
ptrsize() {
    hexlen $1; log2 $(( $? - 1 )); n=$?
    echo "${ptrna[$n]}"
}

process_asm() {
    local distorm=0
    local ndisasm=0
    local s_bytes s_mnem s_addr s_len
    while read -ra input; do
        if [[ $distorm == 0 && $ndisasm == 0 ]]; then
            if [[ ${input[0]} == diStorm ]]; then
                distorm=1
            else
                ndisasm=1
            fi
        fi
                
        array_shift s_addr input
        array_shift s_len input
        if [[ $distorm == 1 ]]; then
            array_shift s_bytes input
            array_shift s_mnem input
            s_opers="${input[*]}"
        else
            s_bytes=$s_len
            array_shift s_mnem input
            s_opers="${input[*]}"
            s_len="(0)"
        fi

        # skip over ndisasm continuation lines
        if [[ $s_addr == -* ]]; then
            continue
        fi

        if [[ $s_addr == 0* || $ndisasm == 1 ]]; then
            # strip leading 0
            addr=$(( 0x$s_addr ))
            # skip over split lines [ndisasm] check 2
            (( addr == 0 )) && continue
            s_mnem=${s_mnem,,}
            s_len=${s_len#(}
            s_len=${s_len#0}
            s_len=${s_len%)}
            s_mnem=${s_mnem%$'\r'}
            s_opers=${s_opers%$'\r'}

            # first things first, replace ndisasm conditionals
            array_find "${s_mnem}" "${condna[@]}"
            ptr_pos=$?
            if (( ptr_pos < 255 )); then
                s_mnem=${condda[$ptr_pos]}
            fi

            # length of byte representation (only in distorm)
            (( len = s_len ))

            # check we actually have operators
            if [[ ! -z "${s_opers// }" ]]; then

                # split operators (and convert to lowercase)
                explode "," "${s_opers,,}"
                array_copy a_opers "${EXPLODED[@]}"
                array_count a_opers
                oper_count=$?
                new_opers=()
                ptr_count=(0 0)
                ptr_words=()
                reg_count=(0 0)
                reg_words=()  # store "clear" registers (where the register is the
                              # only thing in the operand), to compare against size
                              # specifiers in other operand
                            

                (( i = 0 ))
                # for each operator
                for oper in "${a_opers[@]# }"; do
                    s_ptr= # to record any ptr sizes (dword, byte...)
                    s_reg= # to record any operator that is simply a register

                    # we can check for stand-along registers early
                    
                    # check for those operators
                    if in_array "$oper" "${registers[@]}"; then
                        reg_count[$i]=1
                        s_reg=$oper
                    fi


                    # now we can split the operator into it's components
                    explode " " "$oper"
                    array_copy split_oper "${EXPLODED[@]}"

                    # remove `short` from `jmp short` and such [ndisasm]
                    if [[ ${split_oper[0]} == short ]]; then
                        array_shift unused split_oper
                    fi

                    # remove `near` from `jmp near` and such [ndisasm]
                    if [[ ${split_oper[0]} == near ]]; then
                        array_shift unused split_oper
                    fi

                    # check if any ptr sizes are at the start [ndisasm]
                    if in_array "${split_oper[0]}" $ptrn; then
                        s_ptr=${split_oper[0]}
                        ptr_count[$i]=1

                        # check if ptr size is self-evident, e.g. byte 0x1
                        regex='^[+-]?[0-9a-fx]{1,}$' # regex for matching hex or decimal number
                        val_st=${split_oper[1]}
                        if [[ $val_st =~ $regex ]]; then
                            val=$(( $val_st ))
                            
                            # check what the default ptr size for this value would be
                            default_ptr_size=$( ptrsize $val )
                            # echo "$default_ptr_size $val ${split_oper[0]}" >& 2

                            # if the default matches what is obvious, remove it
                            if [[ $default_ptr_size == ${split_oper[0]} ]]; then
                                array_shift unused split_oper
                            fi
                        fi
                    fi

                    for j in "${!split_oper[@]}"; do
                        # remove leading + from immediate values [ndisasm]
                        split_oper[$j]=${split_oper[$j]#+}

                        # translate rip relative addresses into [rel absolute]
                        if [[ ${split_oper[$j]} == \[rip* ]]; then # (balance ] to keep vim happy)
                            regex='^(.rip)([+-][0-9a-fx]{1,})]$'
                            if [[ ${split_oper[$j]} =~ $regex ]]; then
                                offset=$(( ${BASH_REMATCH[2]} ))
                                printf -v split_oper[$j] "[rel 0x%x]" $(( addr + offset + len ))
                            fi
                        fi
                    done

                    # reassemble the operand
                    implode " " "${split_oper[@]}"

                    # record what we found
                    new_opers+=( "$IMPLODED" )
                    ptr_words+=( "$s_ptr" )
                    reg_words+=( "$s_reg" )
                    (( ++i ))
                done

                # distorm doesn't employ superfluous ptr sizes 
                # when they can be deduced from the register size
                # 
                # 1400163de movaps oword [rbp+0x47],xmm1
                # 1400163e2 movups xmm0,oword [rbp+0x17]
                # 
                # we need to remove unnecesary sizes as used by ndisasm,
                # for which we use the information we recorded previously
                if (( reg_count[0] && ptr_count[1] )); then

                    array_find "${ptr_words[1]}" "${ptrna[@]}"
                    ptr_pos=$?
                    if in_array "${reg_words[0]}" ${opsna[$ptr_pos]}; then
                        echo "removing ${ptr_words[1]} from operand 1, due to register of matching size ${reg_words[0]}" >& 2
                        explode " " "${new_opers[1]}"
                        array_copy tmp "${EXPLODED[@]}"
                        # cant shift from EXPLODED because array_shift uses that var
                        array_shift unused tmp
                        implode " " "${tmp[@]}"
                        new_opers[1]=$IMPLODED
                    fi

                fi

                # worst example of code re-use ever, as we swap sides and perform
                # the same operation
                if (( reg_count[1] && ptr_count[0] )); then

                    array_find "${ptr_words[0]}" "${ptrna[@]}"
                    ptr_pos=$?
                    if in_array "${reg_words[1]}" ${opsna[$ptr_pos]}; then
                        echo "removing ${ptr_words[0]} from operand 0, due to register of matching size ${reg_words[1]}" >& 2
                        explode " " "${new_opers[0]}"
                        array_copy tmp "${EXPLODED[@]}"
                        # cant shift from EXPLODED because array_shift uses that var
                        array_shift unused tmp
                        implode " " "${tmp[@]}"
                        new_opers[0]=$IMPLODED
                    fi

                fi


                # now we can assmble the operands together
                implode "," "${new_opers[@]}"

                # and output the final line with address and mnemonic
                printf "%x %s %s\n" "$addr" "$s_mnem" "$IMPLODED"
            else
                printf "%x %s\n" "$addr" "$s_mnem"
            fi
        fi
    done 
}
# process_asm <<< $( ndisasm.exe -b 64 -o 0x140016124 torture.bin )
# process_asm <<< $( ./disasm.exe -b64 torture.bin 0x140016124 )
process_asm <<< $( ndisasm.exe -b 64 -o 0x140016124 torture.bin ) > test-ndisasm.asm
process_asm <<< $( ./disasm.exe -b64 torture.bin 0x140016124 ) > test-distorm.asm

# diff test-ndisasm.asm test-distorm.asm

process_asm <<< $( ndisasm.exe -b 64 -o 0x1432b39b0 exception.bin ) >> test-ndisasm.asm
process_asm <<< $( ./disasm.exe -b64 exception.bin 0x1432b39b0 ) >> test-distorm.asm
diff test-ndisasm.asm test-distorm.asm
