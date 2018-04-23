 /*
  加密程序：实现对文件的加密
*/

#include "md5.h"
#include "AES.h"

//#include "AES_kernel.cu"
//int runTest(char* md5key,char* filepath); //加密
int runTest(char* md5key,unsigned char * Imem,unsigned char * Omem,unsigned long mem_length); 

unsigned long GetFileLen(const char* szFilePath); //得到文件的长度
//extern unsigned char h_Sbox[256];

extern "C" 
int jiami(char* md5key,char* filepath) 
{
	int deviceCount = 0;
	CUDA_SAFE_CALL(cudaGetDeviceCount(&deviceCount));
	
	//没有支持CUDA的设备
	if(deviceCount==0)
	{
		printf("您的设备不支持CUDA！\n");
		return -1;
	}

	//计算驱动版本
    int dev;
	int driverVersion = 0;     
    for (dev = 0; dev < deviceCount; ++dev) 
	{
        cudaDeviceProp deviceProp;
        cudaGetDeviceProperties(&deviceProp, dev);
		if(CUDART_VERSION >= 2020)
		{
			cudaDriverGetVersion(&driverVersion);
			//printf("CUDA Driver Version: %d.%d\n", driverVersion/1000, driverVersion%100);
			if(driverVersion/1000 < 3 || driverVersion/1000 == 3 && driverVersion%100 < 2)
			{
				printf("您的显卡驱动版本太低，请更新显卡驱动！\n");
				return -2;
			}
		}
		else
		{
			printf("您的显卡驱动版本太低，请更新显卡驱动！\n");
			return -2;
		}
	}

	//计算运行时间
	clock_t start,finish;
	double totaltime;
	FILE *fp;   //从文件中读入密文											
	if((fp=fopen(filepath,"rb"))==NULL)
	{
		printf("无法读入您选择的文件\n");
		exit(0);
	}

	unsigned long input_length = GetFileLen( filepath );	               //文件长度
	unsigned long mem_length = (input_length + 1024 * 16 - 1) / 4;	   //存储器长度,按16k分组
	unsigned char *Aes;									               //内存中的密文
	Aes = (unsigned char*) malloc(sizeof(unsigned int) * mem_length);  //在内存上为密文分配空间
	unsigned char *OAes;									               //内存中的密文
	OAes = (unsigned char*) malloc(sizeof(unsigned int) * mem_length);  //在内存上为密文分配空间
	
	fread(Aes, sizeof(unsigned char), input_length, fp);
	for(unsigned int i = input_length; i < 4 * mem_length; i ++)
	{
		Aes[i] = 0;
	}
	fclose(fp);

	start=clock();

	runTest(md5key,Aes,OAes,mem_length);

	finish=clock();
	totaltime=(double)(finish-start)/CLOCKS_PER_SEC;
    printf("\n运行时间为%f秒!\n",totaltime);

	char filename[260];
	strcpy(filename,filepath);	
	strcat(filename,".enc");
	printf("%s",filename);
	//写入输出文件
	FILE* fp_w = fopen(filename,"wb");
	if(fp_w == NULL)
	{
		printf("打开文件失败");
	}
//	int size;
//	size = fwrite(mykey,sizeof(unsigned char),16,fp_w);	//将用户MD5密码写入文件头
//	printf("%d\n",size);
	fwrite(OAes, sizeof(unsigned char), (input_length + 15) / 16 * 16, fp_w);
//	printf("%d\n",size);
	fclose(fp_w);

	// 释放空间
	free(Aes);
	free(OAes);

	finish=clock();
	totaltime=(double)(finish-start)/CLOCKS_PER_SEC;
    printf("\n运行加写文件时间为%f秒!\n",totaltime);
	return 0;
}

// 加密
int runTest(char* md5key,unsigned char * Imem,unsigned char * Omem,unsigned long mem_length) 
{
	unsigned char *IAes;
	unsigned char *OAes;
	unsigned char mykey[16]; //扩展密码 
	int round;
	//MD5扩展用户密码
	MD5 md5;
/*	if(argc < 2)		//无用户密码和文件参数，退出！
	{
		printf("请选择要加密的文件并输入您的密码！\n");
		return -1;
	}
*/
	md5.Data((unsigned char *)md5key,strlen(md5key),mykey);

	//读入要加密的文件
//	for(int k = 2; k < argc; ++k)
//	{
	unsigned int *roundkey;							                   //内存中的密文
	roundkey = (unsigned int*) malloc(sizeof(unsigned int) * 44);	   //在内存上为密文分配空间
	printf("%d\n",mem_length);
	printf("%d\n",PIECE_SIZE);
	if(mem_length < PIECE_SIZE)
	//初始化CUDA运行环境
	{

		printf("+>\n");
		cudaSetDevice(0);	
		printf("123");
		unsigned int* d_roundkey;
		CUDA_SAFE_CALL( cudaMalloc( (void**) &d_roundkey, sizeof(unsigned int) * 44 ));

		AesSetKeyEncode(roundkey, mykey, 16);//计算加密轮密钥,128bit密钥，长度16Byte

		CUDA_SAFE_CALL( cudaMemcpy( d_roundkey, roundkey, sizeof(unsigned int) * 44 ,cudaMemcpyHostToDevice) );	//将轮密钥拷贝到显存中	


		//为密文分配显存
		unsigned int* d_Aes;		
		CUDA_SAFE_CALL( cudaMalloc( (void**) &d_Aes, sizeof(unsigned int) * (mem_length )));

		//为输出分配显存
		unsigned int* d_OAes;			
		CUDA_SAFE_CALL( cudaMalloc( (void**) &d_OAes, sizeof(unsigned int) * mem_length ));

		//将密文拷贝到显存中
		CUDA_SAFE_CALL( cudaMemcpy( d_Aes, Imem, sizeof(unsigned int) * mem_length, cudaMemcpyHostToDevice) );

		// 设置运行参数
		dim3  grid( (mem_length ) / BLOCK_SIZE / LOOP_IN_BLOCK , 1, 1);		//定义grid, grid大小为 密文长度/ 一个BLOCK中处理的32bit integer数 / BLOCK中循环次数												
		dim3  threads( BLOCK_SIZE, 1, 1);

		/*加密开始*/

								
		printf("正在加密...\n");
		AES128_EBC_encry_kernel<<< grid, threads>>>(d_Aes, d_OAes, d_roundkey); //加密程序内核

		CUT_CHECK_ERROR("CUDA内核执行失败！\n");	//检查是否正确执行


		CUDA_SAFE_CALL( cudaMemcpy( Omem, d_OAes, sizeof(unsigned int) * mem_length,cudaMemcpyDeviceToHost) );//将输出从显存拷贝到内存	
			
		//定义输出文件的文件名

		free(roundkey);

		CUDA_SAFE_CALL(cudaFree(d_Aes));
		CUDA_SAFE_CALL(cudaFree(d_OAes));
		CUDA_SAFE_CALL(cudaFree(d_roundkey));
	}
	else
	{
		printf("+>\n");

		IAes = Imem;
		OAes = Omem;
		unsigned long mem_remainder;
		int time;
		round = mem_length/PIECE_SIZE;		 //64M分组
		mem_remainder = mem_length%PIECE_SIZE;
		printf("正在加密...\n");
		cudaSetDevice(0);	

		unsigned int* d_roundkey;
		CUDA_SAFE_CALL( cudaMalloc( (void**) &d_roundkey, sizeof(unsigned int) * 44 ));


		AesSetKeyEncode(roundkey, mykey, 16);//计算加密轮密钥,128bit密钥，长度16Byte

		CUDA_SAFE_CALL( cudaMemcpy( d_roundkey, roundkey, sizeof(unsigned int) * 44 ,cudaMemcpyHostToDevice) );	//将轮密钥拷贝到显存中	
		unsigned int* d_Aes;		

		unsigned int* d_OAes;			

		//为密文分配显存
		CUDA_SAFE_CALL( cudaMalloc( (void**) &d_Aes, sizeof(unsigned int) * PIECE_SIZE));

		//为输出分配显存
		CUDA_SAFE_CALL( cudaMalloc( (void**) &d_OAes, sizeof(unsigned int) * PIECE_SIZE));
		printf("%d\n",round);
		for(time = 0;time < round;time++)
		{

			//将密文拷贝到显存中
			CUDA_SAFE_CALL( cudaMemcpy( d_Aes, IAes, sizeof(unsigned int) * PIECE_SIZE, cudaMemcpyHostToDevice) );

			// 设置运行参数
			dim3  grid( PIECE_SIZE / BLOCK_SIZE / LOOP_IN_BLOCK , 1, 1);		//定义grid, grid大小为 密文长度/ 一个BLOCK中处理的32bit integer数 / BLOCK中循环次数												
			dim3  threads( BLOCK_SIZE, 1, 1);

			/*加密开始*/
									
			AES128_EBC_encry_kernel<<< grid, threads>>>(d_Aes, d_OAes, d_roundkey); //加密程序内核
//			Sleep(5000);
			CUT_CHECK_ERROR("CUDA内核执行失败！\n");	//检查是否正确执行

			printf("%d\n",IAes);
			printf("%d\n",OAes);
			CUDA_SAFE_CALL( cudaMemcpy( OAes, d_OAes, sizeof(unsigned int) * PIECE_SIZE,cudaMemcpyDeviceToHost) );//将输出从显存拷贝到内存	
			IAes = Imem + (time + 1)*PIECE_SIZE*4;
			OAes = Omem + (time + 1)*PIECE_SIZE*4;

		}	
		//定义输出文件的文件名
//		CUDA_SAFE_CALL(cudaFree(d_Aes));
//		CUDA_SAFE_CALL(cudaFree(d_OAes));



//		CUDA_SAFE_CALL( cudaMalloc( (void**) &d_Aes, sizeof(unsigned int) * (mem_remainder)));
//		CUDA_SAFE_CALL( cudaMalloc( (void**) &d_OAes, sizeof(unsigned int) * (mem_remainder)));
		CUDA_SAFE_CALL( cudaMemcpy( d_Aes, IAes, sizeof(unsigned int) * (mem_remainder), cudaMemcpyHostToDevice) );
		printf("%d\n",mem_remainder);
		// 设置运行参数
		dim3  grid( (mem_remainder) / BLOCK_SIZE / LOOP_IN_BLOCK , 1, 1);		//定义grid, grid大小为 密文长度/ 一个BLOCK中处理的32bit integer数 / BLOCK中循环次数												
		dim3  threads( BLOCK_SIZE, 1, 1);

		/*加密开始*/
								
		AES128_EBC_encry_kernel<<< grid, threads>>>(d_Aes, d_OAes, d_roundkey); //加密程序内核

		CUT_CHECK_ERROR("CUDA内核执行失败！\n");	//检查是否正确执行


		CUDA_SAFE_CALL( cudaMemcpy( OAes, d_OAes, sizeof(unsigned int) * mem_remainder,cudaMemcpyDeviceToHost) );//将输出从显存拷贝到内存	

		free(roundkey);
		CUDA_SAFE_CALL(cudaFree(d_Aes));
		CUDA_SAFE_CALL(cudaFree(d_OAes));

		CUDA_SAFE_CALL(cudaFree(d_roundkey));	
	}
//	}	
	return 0;
}
	
unsigned long GetFileLen(const char* szFilePath)  //得到文件的长度
{
	FILE* pFile = fopen(szFilePath, "rb");
	if (pFile == NULL)
		return -1;

	fseek(pFile, 0, SEEK_END);
	long nFileLen = ftell(pFile);
	fclose(pFile);

	return nFileLen;
}
