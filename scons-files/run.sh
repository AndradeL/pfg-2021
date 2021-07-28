for dir in ./*/
do
	cd $dir
	echo `pwd`
	scons -c
	scons
	cd ..
done
