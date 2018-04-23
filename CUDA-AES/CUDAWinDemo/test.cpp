#include "AES.h"

int main()	   
{
	char	filepath[1024] = "test.mp4";
	
	jiami("12345687",filepath);
	strcat(filepath,".enc");
	jiemi("12345687",filepath);

	system("pause");

	return 0;
}