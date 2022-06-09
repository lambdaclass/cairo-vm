text="func main():
        "
for i in $(seq 500 $END); do 
        text+="[ap] = $i;ap++
        [ap] = [ap - 1] * [ap - 1]; ap++
        "; 
done

text+="ret
end"
echo "$text" > generate_variables.cairo
cairo-compile generate_variables.cairo --output generate_variables.json
rm generate_variables.cairo
