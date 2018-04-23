#include "AES.h"

int main()	   
{
	char	filepath[1024] = "test.mp4";
	
	jiami("0123456789abcdef",filepath);
	strcat(filepath,".enc");
	jiemi("0123456789abcdef",filepath);

	system("pause");

	return 0;
}