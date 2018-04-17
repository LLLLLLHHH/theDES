/*-------------------------------------------------------
Data Encryption Standard  56位密钥加密64位数据
--------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include "bool.h"   // 位处理 
#include "tables.h"

void BitsCopy(bool *DatOut, bool *DatIn, int Len);  // 数组复制 

void ByteToBit(bool *DatOut, char *DatIn, int Num); // 字节到位 
void BitToByte(char *DatOut, bool *DatIn, int Num); // 位到字节

void BitToHex(char *DatOut, bool *DatIn, int Num);  // 二进制到十六进制 64位 to 4*16字符
void HexToBit(bool *DatOut, char *DatIn, int Num);  // 十六进制到二进制 

void TablePermute(bool *DatOut, bool *DatIn, const char *Table, int Num); // 位表置换函数 
void LoopMove(bool *DatIn, int Len, int Num);     // 循环左移 Len长度 Num移动位数 
void Xor(bool *DatA, bool *DatB, int Num);         // 异或函数 

void S_Change(bool DatOut[32], bool DatIn[48]);   // S盒变换 
void F_Change(bool DatIn[32], bool DatKi[48]);    // F函数                                  

void SetKey(char KeyIn[8]);                         // 设置密钥
void PlayDes(char MesOut[8], char MesIn[8]);       // 执行DES加密
void KickDes(char MesOut[8], char MesIn[8]);             // 执行DES解密 

/*-------------------------------
把DatIn开始的长度位Len位的二进制
复制到DatOut后
--------------------------------*/
void BitsCopy(bool *DatOut, bool *DatIn, int Len)     // 数组复制 OK 
{
	int i = 0;
	for (i = 0;i<Len;i++)
	{
		DatOut[i] = DatIn[i];
	}
}

/*-------------------------------
字节转换成位函数
每8次换一个字节 每次向右移一位
和1与取最后一位 共64位
--------------------------------*/
void ByteToBit(bool *DatOut, char *DatIn, int Num)       // OK
{
	int i = 0;
	for (i = 0;i<Num;i++)
	{
		DatOut[i] = (DatIn[i / 8] >> (i % 8)) & 0x01;
	}
}

/*-------------------------------
位转换成字节函数
字节数组每8次移一位
位每次向左移 与上一次或
---------------------------------*/
void BitToByte(char *DatOut, bool *DatIn, int Num)        // OK
{
	int i = 0;
	for (i = 0;i<(Num / 8);i++)
	{
		DatOut[i] = 0;
	}
	for (i = 0;i<Num;i++)
	{
		DatOut[i / 8] |= DatIn[i] << (i % 8);
	}
}


/*----------------------------------
二进制密文转换为十六进制
需要16个字符表示
-----------------------------------*/
void BitToHex(char *DatOut, bool *DatIn, int Num)
{
	int i = 0;
	for (i = 0;i<Num / 4;i++)
	{
		DatOut[i] = 0;
	}
	for (i = 0;i<Num / 4;i++)
	{
		DatOut[i] = DatIn[i * 4] + (DatIn[i * 4 + 1] << 1)
			+ (DatIn[i * 4 + 2] << 2) + (DatIn[i * 4 + 3] << 3);
		if ((DatOut[i] % 16)>9)
		{
			DatOut[i] = DatOut[i] % 16 + '7';       //  余数大于9时处理 10-15 to A-F
		}                                     //  输出字符 
		else
		{
			DatOut[i] = DatOut[i] % 16 + '0';       //  输出字符       
		}
	}

}

/*---------------------------------------------
十六进制字符转二进制
----------------------------------------------*/
void HexToBit(bool *DatOut, char *DatIn, int Num)
{
	int i = 0;                        // 字符型输入 
	for (i = 0;i<Num;i++)
	{
		if ((DatIn[i / 4])>'9')         //  大于9 
		{
			DatOut[i] = ((DatIn[i / 4] - '7') >> (i % 4)) & 0x01;
		}
		else
		{
			DatOut[i] = ((DatIn[i / 4] - '0') >> (i % 4)) & 0x01;
		}
	}
}

// 表置换函数  OK
void TablePermute(bool *DatOut, bool *DatIn, const char *Table, int Num)
{
	int i = 0;
	static bool Temp[256] = { 0 };
	for (i = 0;i<Num;i++)                // Num为置换的长度 
	{
		Temp[i] = DatIn[Table[i] - 1];  // 原来的数据按对应的表上的位置排列 
	}
	BitsCopy(DatOut, Temp, Num);       // 把缓存Temp的值输出 
}

// 子密钥的移位
void LoopMove(bool *DatIn, int Len, int Num) // 循环左移 Len数据长度 Num移动位数
{
	static bool Temp[256] = { 0 };    // 缓存   OK
	BitsCopy(Temp, DatIn, Num);       // 将数据最左边的Num位(被移出去的)存入Temp 
	BitsCopy(DatIn, DatIn + Num, Len - Num); // 将数据左边开始的第Num移入原来的空间
	BitsCopy(DatIn + Len - Num, Temp, Num);  // 将缓存中移出去的数据加到最右边 
}

// 按位异或
void Xor(bool *DatA, bool *DatB, int Num)           // 异或函数
{
	int i = 0;
	for (i = 0;i<Num;i++)
	{
		DatA[i] = DatA[i] ^ DatB[i];                  // 异或 
	}
}

// 输入48位 输出32位 与Ri异或
void S_Change(bool DatOut[32], bool DatIn[48])     // S盒变换
{
	int i, X, Y;                                    // i为8个S盒 
	for (i = 0, Y = 0, X = 0;i<8;i++, DatIn += 6, DatOut += 4)   // 每执行一次,输入数据偏移6位 
	{                                              // 每执行一次,输出数据偏移4位
		Y = (DatIn[0] << 1) + DatIn[5];                          // af代表第几行
		X = (DatIn[1] << 3) + (DatIn[2] << 2) + (DatIn[3] << 1) + DatIn[4]; // bcde代表第几列
		ByteToBit(DatOut, &S_Box[i][Y][X], 4);      // 把找到的点数据换为二进制    
	}
}

// F函数
void F_Change(bool DatIn[32], bool DatKi[48])       // F函数
{
	static bool MiR[48] = { 0 };             // 输入32位通过E选位变为48位
	TablePermute(MiR, DatIn, E_Table, 48);
	Xor(MiR, DatKi, 48);                   // 和子密钥异或
	S_Change(DatIn, MiR);                 // S盒变换
	TablePermute(DatIn, DatIn, P_Table, 32);   // P置换后输出
}

void SetKey(char KeyIn[8])               // 设置密钥 获取子密钥Ki 
{
	int i = 0;
	static bool KeyBit[64] = { 0 };                // 密钥二进制存储空间 
	static bool *KiL = &KeyBit[0], *KiR = &KeyBit[28];  // 前28,后28共56
	ByteToBit(KeyBit, KeyIn, 64);                    // 把密钥转为二进制存入KeyBit 
	TablePermute(KeyBit, KeyBit, PC1_Table, 56);      // PC1表置换 56次
	for (i = 0;i<16;i++)
	{
		LoopMove(KiL, 28, Move_Table[i]);       // 前28位左移 
		LoopMove(KiR, 28, Move_Table[i]);          // 后28位左移 
		TablePermute(SubKey[i], KeyBit, PC2_Table, 48);
		// 二维数组 SubKey[i]为每一行起始地址 
		// 每移一次位进行PC2置换得 Ki 48位 
	}
}

void PlayDes(char MesOut[8], char MesIn[8])  // 执行DES加密
{                                           // 字节输入 Bin运算 Hex输出 
	int i = 0;
	static bool MesBit[64] = { 0 };        // 明文二进制存储空间 64位
	static bool Temp[32] = { 0 };
	static bool *MiL = &MesBit[0], *MiR = &MesBit[32]; // 前32位 后32位 
	ByteToBit(MesBit, MesIn, 64);                 // 把明文换成二进制存入MesBit
	TablePermute(MesBit, MesBit, IP_Table, 64);    // IP置换 
	for (i = 0;i<16;i++)                       // 迭代16次 
	{
		BitsCopy(Temp, MiR, 32);            // 临时存储
		F_Change(MiR, SubKey[i]);           // F函数变换
		Xor(MiR, MiL, 32);                  // 得到Ri 
		BitsCopy(MiL, Temp, 32);            // 得到Li 
	}
	TablePermute(MesBit, MesBit, IPR_Table, 64);
	BitToHex(MesOut, MesBit, 64);
}

void KickDes(char MesOut[8], char MesIn[8])       // 执行DES解密
{                                                // Hex输入 Bin运算 字节输出 
	int i = 0;
	static bool MesBit[64] = { 0 };        // 密文二进制存储空间 64位
	static bool Temp[32] = { 0 };
	static bool *MiL = &MesBit[0], *MiR = &MesBit[32]; // 前32位 后32位
	HexToBit(MesBit, MesIn, 64);                 // 把密文换成二进制存入MesBit
	TablePermute(MesBit, MesBit, IP_Table, 64);    // IP置换 
	for (i = 15;i >= 0;i--)
	{
		BitsCopy(Temp, MiL, 32);
		F_Change(MiL, SubKey[i]);
		Xor(MiL, MiR, 32);
		BitsCopy(MiR, Temp, 32);
	}
	TablePermute(MesBit, MesBit, IPR_Table, 64);
	BitToByte(MesOut, MesBit, 64);
}

int yuanmain()
{
	int i = 0;
	char MesHex[16] = { 0 };         // 16个字符数组用于存放 64位16进制的密文
	char MyKey[8] = { 0 };           // 初始密钥 8字节*8
	char YourKey[8] = { 0 };         // 输入的解密密钥 8字节*8
	char MyMessage[8] = { 0 };       // 初始明文 

									 /*-----------------------------------------------*/

	printf("Welcome! Please input your Message(64 bit):\n");
	gets(MyMessage);            // 明文
	printf("Please input your Secret Key:\n");
	gets(MyKey);                // 密钥

	while (MyKey[i] != '\0')        // 计算密钥长度
	{
		i++;
	}

	while (i != 8)                  // 不是8 提示错误
	{
		printf("Please input a correct Secret Key!\n");
		gets(MyKey);
		i = 0;
		while (MyKey[i] != '\0')    // 再次检测
		{
			i++;
		}
	}

	SetKey(MyKey);               // 设置密钥 得到子密钥Ki

	PlayDes(MesHex, MyMessage);   // 执行DES加密

	printf("Your Message is Encrypted!:\n");  // 信息已加密
	for (i = 0;i<16;i++)
	{
		printf("%c ", MesHex[i]);
	}
	printf("\n\n");

	printf("Please input your Secret Key to Deciphering:\n");  // 请输入密钥以解密
	gets(YourKey);                                         // 得到密钥
	SetKey(YourKey);                                       // 设置密钥

	KickDes(MyMessage, MesHex);                     // 解密输出到MyMessage

	printf("Deciphering Over !!:\n");                     // 解密结束
	for (i = 0;i<8;i++)
	{
		printf("%c ", MyMessage[i]);
	}
	printf("\n\n");

	/*------------------------------------------------*/
	return 0;
}

void IntToBit(int num,bool *bit,int i) {
	int n = num;
	while (i) {
		bit[--i] = n % 2;
		n /= 2;
	}
}

void printfdiff(diffop* op) {
	int i;bool temp[4];bool hang[2];int j;
	diffop* pointer;
	for (i=0;i < 16;i++) {
		pointer = &op[i];
		IntToBit(i, temp, 4);
		printf("\n\t");
		for (j = 0;j < 4;j++) {
			printf("%d", temp[j]);
		}printf("   	->  	");j = 0;
		while (pointer != NULL) {
			if (pointer->num != -1) {
				IntToBit(pointer->lie, temp, 4);IntToBit(pointer->hang, hang, 2);
				printf("%d%d%d%d%d%d   ", hang[0], temp[0], temp[1], temp[2], temp[3], hang[1]);
				j++;
			}
			pointer = pointer->next;
		}printf(" %d", j);
	}
}

void intts_op(diffop* sop) {
	for (int i = 0;i < 80;i++) {
		sop[i].next = NULL;sop[i].num = -1;
	}
}

void differcal(int cha,int sbox) {
	bool chafen[6];
	IntToBit(cha, chafen, 6);
	int hang,lie;
	diffop* pointer=NULL;
	
	int i,j,x;int temp;bool data[6],data2[6];
	diffop s_op[80];intts_op(s_op);//s_op=(diffop*)malloc(sizeof(diffop) * 80);
	bool used[64] = { 0 };
	for (i = 0;i < 64;i++) {
		if (used[i] == 0) {
			if (i == 6) {
				i = 6;
			};
			used[i] = 1;
			IntToBit(i, data, 6);
			hang = data[0] * 2 + data[5];
			lie = data[4] + data[3] * 2 + data[2] * 4 + data[1] * 8;
			s_op[16 + i].hang = hang;
			s_op[16 + i].lie = lie;
			s_op[16 + i].num = S_Box[sbox][hang][lie];

			Xor(data, chafen, 6);

			hang = data[0] * 2 + data[5];
			lie = data[4] + data[3] * 2 + data[2] * 4 + data[1] * 8;
			j = hang * 16 + lie;
			x = data[5] + data[4] * 2 + data[3] * 4 + data[2] * 8 + data[1] * 16 + data[0] * 32;
			used[x] = 1;
			s_op[16 + x].hang = hang;
			s_op[16 + x].lie = lie;
			s_op[16 + x].num = S_Box[sbox][hang][lie];
			s_op[16 + i].next = &s_op[16 + x];

			//temp = abs(s_op[16 + i].num - s_op[16 + x].num);//计算输出差分
			IntToBit(s_op[16 + i].num, data, 4);
			IntToBit(s_op[16 + x].num, data2, 4);
			Xor(data, data2, 4);
			temp = data[3] + data[2] * 2 + data[1] * 4 + data[0] * 8;
			pointer = &s_op[temp];

			while (pointer->next != NULL) {
				pointer = pointer->next;
			}
			pointer->next = &s_op[16 + i];
			pointer->next->next->next = NULL;
			pointer = NULL;
		}
		
	}
	
	printfdiff(s_op);


}

int chafenfx() {
	int cha;
	int sbno;
	printf("输入差分值(0-63) ：");
	scanf("%d", &cha);

	printf("输入s盒值(1-8) ：");
	scanf("%d", &sbno);

	differcal(cha, sbno - 1);

	getchar();
	getchar();
	return 0;
}

int cal_differ_DES(char *meshex,char *mes2) {
	int i;
	int j = 0;
	bool bedes[64] = { 0 };
	bool afdes[64] = { 0 };
	HexToBit(bedes,mes2 , 64);
	HexToBit(afdes,meshex , 64);
	for (i = 0;i < 64;i++) {
		if (bedes[i] != afdes[i])j += 1;
	}
	return j;
}

void get_randm(int *randm) {
	int i,j;
	int ra;
	for (i = 0;i < 64;i++) {
		ra = rand() % 64+1;
		for (j = 0;j < i;j++) {
			if (randm[j] == ra) {
				ra = rand() % 64 + 1;
				j = 0;
			}
		}randm[i] = ra;
	}
}

void printf_cal(int *cal) {
	int i,j;
	printf("  ");
	for (i = 0;i <= 64;i++) {
		if (cal[i] == 0) {
			printf("  %d : %d ", i, cal[i]);
		}else printf("\n  %d : %d ", i, cal[i]);
	for (j = 0;j < cal[i]/10;j++) {
			printf("*");
		}
	}
}

void change_mes(char* mes,int* cal,char* key) {
	int i, j;int k;
	int randm[64] = { 0 };
	bool mess[64] = { 0 };
	char MesHex[16] = { 0 };
	char mes2[16] = { 0 };
	
	
	SetKey(key);               // 设置密钥 得到子密钥Ki
	PlayDes(MesHex, mes);

	for(i = 1;i <= 64;i++) {
		for (k = 0;k < 10000;k++) {
			get_randm(randm);
			ByteToBit(mess, mes, 64);
			for (j = 0;j < i;j++) {
				mess[randm[(k + j) % 64]] = !mess[randm[(k + j) % 64]];
			}
			BitToByte(mes, mess, 64);
			PlayDes(mes2, mes);   // 执行DES加密
			cal[cal_differ_DES(MesHex, mes2)] += 1;
		}
		printf("\n 改变 %d 位：", i);
		printf_cal(cal);
		for (j = 0;j <= 64;j++)cal[j] = 0;
	}
	
	
}

void change_key(char* mes, int* cal, char* key) {
	int i, j;int k;
	int randm[64] = { 0 };
	bool mess[64] = { 0 };
	char MesHex[16] = { 0 };
	char mes2[16] = { 0 };


	SetKey(key);               // 设置密钥 得到子密钥Ki
	PlayDes(MesHex, mes);

	for (i = 1;i <= 64;i++) {
		for (k = 0;k < 10000;k++) {
			get_randm(randm);
			ByteToBit(mess, key, 64);
			for (j = 0;j < i;j++) {
				mess[randm[(k + j) % 64]] = !mess[randm[(k + j) % 64]];
			}
			BitToByte(key, mess, 64);
			SetKey(key);
			PlayDes(mes2, mes);   // 执行DES加密
			cal[cal_differ_DES(MesHex, mes2)] += 1;
		}
		printf("\n 改变 %d 位：", i);
		printf_cal(cal);
		for (j = 0;j <= 64;j++)cal[j] = 0;
	}

}

int canzhaofx(int chose) {
	int i = 0;
	int caldif[65] = { 0 };
	char MesHex[16] = { 0 };         // 16个字符数组用于存放 64位16进制的密文
	char MyKey[8] = { 0 };           // 初始密钥 8字节*8
	char MyMessage[8] = { 0 };       // 初始明文 


	printf("输入加密信息(64 bit):\n");
	gets(MyMessage);            // 明文
	printf("输入8位密钥:\n");
	gets(MyKey);                // 密钥

	while (MyKey[i] != '\0'){   // 计算密钥长度
		i++;
	}
	while (i != 8){ // 不是8 提示错误
		printf("密钥长度错误!\n");
		gets(MyKey);
		i = 0;
		while (MyKey[i] != '\0'){ // 再次检测
			i++;
		}
	}
	if (chose == 2)change_mes(MyMessage, caldif, MyKey);
	else change_key(MyMessage, caldif, MyKey);

	return 0;
}

int main() {
	int chose = -1;
	while (chose != 0) {
		printf("1:差分分析 \n2:密钥不变分析\n3:明文不变分析\n0:exit\n");
		scanf("%d", &chose);
		if (chose == 1) {
			chafenfx();
		}
		else if (chose == 2 || chose == 3) {
			canzhaofx(chose);
		}
	}
	getchar();getchar();
	return 0;
}