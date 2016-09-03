GP_PATH=/home/cranix/JavaCard/GlobalPlatformPro

all:
	@ant

flash:

	@java -jar $(GP_PATH)/gp.jar --install passmg.cap
	@java -jar $(GP_PATH)/gp.jar --cap passmg.cap --create A1000000000301

delete:
	@java -jar $(GP_PATH)/gp.jar --delete A100000000 --deletedeps	

