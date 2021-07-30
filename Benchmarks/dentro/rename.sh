for folder in ./*/
do
    cd $folder/enclave
    echo `pwd`
    mv fwi.c main.c
    cd ../../
done
