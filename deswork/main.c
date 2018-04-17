/*-------------------------------------------------------
Data Encryption Standard  56λ��Կ����64λ����
--------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include "bool.h"   // λ���� 
#include "tables.h"

void BitsCopy(bool *DatOut, bool *DatIn, int Len);  // ���鸴�� 

void ByteToBit(bool *DatOut, char *DatIn, int Num); // �ֽڵ�λ 
void BitToByte(char *DatOut, bool *DatIn, int Num); // λ���ֽ�

void BitToHex(char *DatOut, bool *DatIn, int Num);  // �����Ƶ�ʮ������ 64λ to 4*16�ַ�
void HexToBit(bool *DatOut, char *DatIn, int Num);  // ʮ�����Ƶ������� 

void TablePermute(bool *DatOut, bool *DatIn, const char *Table, int Num); // λ���û����� 
void LoopMove(bool *DatIn, int Len, int Num);     // ѭ������ Len���� Num�ƶ�λ�� 
void Xor(bool *DatA, bool *DatB, int Num);         // ����� 

void S_Change(bool DatOut[32], bool DatIn[48]);   // S�б任 
void F_Change(bool DatIn[32], bool DatKi[48]);    // F����                                  

void SetKey(char KeyIn[8]);                         // ������Կ
void PlayDes(char MesOut[8], char MesIn[8]);       // ִ��DES����
void KickDes(char MesOut[8], char MesIn[8]);             // ִ��DES���� 

/*-------------------------------
��DatIn��ʼ�ĳ���λLenλ�Ķ�����
���Ƶ�DatOut��
--------------------------------*/
void BitsCopy(bool *DatOut, bool *DatIn, int Len)     // ���鸴�� OK 
{
	int i = 0;
	for (i = 0;i<Len;i++)
	{
		DatOut[i] = DatIn[i];
	}
}

/*-------------------------------
�ֽ�ת����λ����
ÿ8�λ�һ���ֽ� ÿ��������һλ
��1��ȡ���һλ ��64λ
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
λת�����ֽں���
�ֽ�����ÿ8����һλ
λÿ�������� ����һ�λ�
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
����������ת��Ϊʮ������
��Ҫ16���ַ���ʾ
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
			DatOut[i] = DatOut[i] % 16 + '7';       //  ��������9ʱ���� 10-15 to A-F
		}                                     //  ����ַ� 
		else
		{
			DatOut[i] = DatOut[i] % 16 + '0';       //  ����ַ�       
		}
	}

}

/*---------------------------------------------
ʮ�������ַ�ת������
----------------------------------------------*/
void HexToBit(bool *DatOut, char *DatIn, int Num)
{
	int i = 0;                        // �ַ������� 
	for (i = 0;i<Num;i++)
	{
		if ((DatIn[i / 4])>'9')         //  ����9 
		{
			DatOut[i] = ((DatIn[i / 4] - '7') >> (i % 4)) & 0x01;
		}
		else
		{
			DatOut[i] = ((DatIn[i / 4] - '0') >> (i % 4)) & 0x01;
		}
	}
}

// ���û�����  OK
void TablePermute(bool *DatOut, bool *DatIn, const char *Table, int Num)
{
	int i = 0;
	static bool Temp[256] = { 0 };
	for (i = 0;i<Num;i++)                // NumΪ�û��ĳ��� 
	{
		Temp[i] = DatIn[Table[i] - 1];  // ԭ�������ݰ���Ӧ�ı��ϵ�λ������ 
	}
	BitsCopy(DatOut, Temp, Num);       // �ѻ���Temp��ֵ��� 
}

// ����Կ����λ
void LoopMove(bool *DatIn, int Len, int Num) // ѭ������ Len���ݳ��� Num�ƶ�λ��
{
	static bool Temp[256] = { 0 };    // ����   OK
	BitsCopy(Temp, DatIn, Num);       // ����������ߵ�Numλ(���Ƴ�ȥ��)����Temp 
	BitsCopy(DatIn, DatIn + Num, Len - Num); // ��������߿�ʼ�ĵ�Num����ԭ���Ŀռ�
	BitsCopy(DatIn + Len - Num, Temp, Num);  // ���������Ƴ�ȥ�����ݼӵ����ұ� 
}

// ��λ���
void Xor(bool *DatA, bool *DatB, int Num)           // �����
{
	int i = 0;
	for (i = 0;i<Num;i++)
	{
		DatA[i] = DatA[i] ^ DatB[i];                  // ��� 
	}
}

// ����48λ ���32λ ��Ri���
void S_Change(bool DatOut[32], bool DatIn[48])     // S�б任
{
	int i, X, Y;                                    // iΪ8��S�� 
	for (i = 0, Y = 0, X = 0;i<8;i++, DatIn += 6, DatOut += 4)   // ÿִ��һ��,��������ƫ��6λ 
	{                                              // ÿִ��һ��,�������ƫ��4λ
		Y = (DatIn[0] << 1) + DatIn[5];                          // af����ڼ���
		X = (DatIn[1] << 3) + (DatIn[2] << 2) + (DatIn[3] << 1) + DatIn[4]; // bcde����ڼ���
		ByteToBit(DatOut, &S_Box[i][Y][X], 4);      // ���ҵ��ĵ����ݻ�Ϊ������    
	}
}

// F����
void F_Change(bool DatIn[32], bool DatKi[48])       // F����
{
	static bool MiR[48] = { 0 };             // ����32λͨ��Eѡλ��Ϊ48λ
	TablePermute(MiR, DatIn, E_Table, 48);
	Xor(MiR, DatKi, 48);                   // ������Կ���
	S_Change(DatIn, MiR);                 // S�б任
	TablePermute(DatIn, DatIn, P_Table, 32);   // P�û������
}

void SetKey(char KeyIn[8])               // ������Կ ��ȡ����ԿKi 
{
	int i = 0;
	static bool KeyBit[64] = { 0 };                // ��Կ�����ƴ洢�ռ� 
	static bool *KiL = &KeyBit[0], *KiR = &KeyBit[28];  // ǰ28,��28��56
	ByteToBit(KeyBit, KeyIn, 64);                    // ����ԿתΪ�����ƴ���KeyBit 
	TablePermute(KeyBit, KeyBit, PC1_Table, 56);      // PC1���û� 56��
	for (i = 0;i<16;i++)
	{
		LoopMove(KiL, 28, Move_Table[i]);       // ǰ28λ���� 
		LoopMove(KiR, 28, Move_Table[i]);          // ��28λ���� 
		TablePermute(SubKey[i], KeyBit, PC2_Table, 48);
		// ��ά���� SubKey[i]Ϊÿһ����ʼ��ַ 
		// ÿ��һ��λ����PC2�û��� Ki 48λ 
	}
}

void PlayDes(char MesOut[8], char MesIn[8])  // ִ��DES����
{                                           // �ֽ����� Bin���� Hex��� 
	int i = 0;
	static bool MesBit[64] = { 0 };        // ���Ķ����ƴ洢�ռ� 64λ
	static bool Temp[32] = { 0 };
	static bool *MiL = &MesBit[0], *MiR = &MesBit[32]; // ǰ32λ ��32λ 
	ByteToBit(MesBit, MesIn, 64);                 // �����Ļ��ɶ����ƴ���MesBit
	TablePermute(MesBit, MesBit, IP_Table, 64);    // IP�û� 
	for (i = 0;i<16;i++)                       // ����16�� 
	{
		BitsCopy(Temp, MiR, 32);            // ��ʱ�洢
		F_Change(MiR, SubKey[i]);           // F�����任
		Xor(MiR, MiL, 32);                  // �õ�Ri 
		BitsCopy(MiL, Temp, 32);            // �õ�Li 
	}
	TablePermute(MesBit, MesBit, IPR_Table, 64);
	BitToHex(MesOut, MesBit, 64);
}

void KickDes(char MesOut[8], char MesIn[8])       // ִ��DES����
{                                                // Hex���� Bin���� �ֽ���� 
	int i = 0;
	static bool MesBit[64] = { 0 };        // ���Ķ����ƴ洢�ռ� 64λ
	static bool Temp[32] = { 0 };
	static bool *MiL = &MesBit[0], *MiR = &MesBit[32]; // ǰ32λ ��32λ
	HexToBit(MesBit, MesIn, 64);                 // �����Ļ��ɶ����ƴ���MesBit
	TablePermute(MesBit, MesBit, IP_Table, 64);    // IP�û� 
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
	char MesHex[16] = { 0 };         // 16���ַ��������ڴ�� 64λ16���Ƶ�����
	char MyKey[8] = { 0 };           // ��ʼ��Կ 8�ֽ�*8
	char YourKey[8] = { 0 };         // ����Ľ�����Կ 8�ֽ�*8
	char MyMessage[8] = { 0 };       // ��ʼ���� 

									 /*-----------------------------------------------*/

	printf("Welcome! Please input your Message(64 bit):\n");
	gets(MyMessage);            // ����
	printf("Please input your Secret Key:\n");
	gets(MyKey);                // ��Կ

	while (MyKey[i] != '\0')        // ������Կ����
	{
		i++;
	}

	while (i != 8)                  // ����8 ��ʾ����
	{
		printf("Please input a correct Secret Key!\n");
		gets(MyKey);
		i = 0;
		while (MyKey[i] != '\0')    // �ٴμ��
		{
			i++;
		}
	}

	SetKey(MyKey);               // ������Կ �õ�����ԿKi

	PlayDes(MesHex, MyMessage);   // ִ��DES����

	printf("Your Message is Encrypted!:\n");  // ��Ϣ�Ѽ���
	for (i = 0;i<16;i++)
	{
		printf("%c ", MesHex[i]);
	}
	printf("\n\n");

	printf("Please input your Secret Key to Deciphering:\n");  // ��������Կ�Խ���
	gets(YourKey);                                         // �õ���Կ
	SetKey(YourKey);                                       // ������Կ

	KickDes(MyMessage, MesHex);                     // ���������MyMessage

	printf("Deciphering Over !!:\n");                     // ���ܽ���
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

			//temp = abs(s_op[16 + i].num - s_op[16 + x].num);//����������
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
	printf("������ֵ(0-63) ��");
	scanf("%d", &cha);

	printf("����s��ֵ(1-8) ��");
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
	
	
	SetKey(key);               // ������Կ �õ�����ԿKi
	PlayDes(MesHex, mes);

	for(i = 1;i <= 64;i++) {
		for (k = 0;k < 10000;k++) {
			get_randm(randm);
			ByteToBit(mess, mes, 64);
			for (j = 0;j < i;j++) {
				mess[randm[(k + j) % 64]] = !mess[randm[(k + j) % 64]];
			}
			BitToByte(mes, mess, 64);
			PlayDes(mes2, mes);   // ִ��DES����
			cal[cal_differ_DES(MesHex, mes2)] += 1;
		}
		printf("\n �ı� %d λ��", i);
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


	SetKey(key);               // ������Կ �õ�����ԿKi
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
			PlayDes(mes2, mes);   // ִ��DES����
			cal[cal_differ_DES(MesHex, mes2)] += 1;
		}
		printf("\n �ı� %d λ��", i);
		printf_cal(cal);
		for (j = 0;j <= 64;j++)cal[j] = 0;
	}

}

int canzhaofx(int chose) {
	int i = 0;
	int caldif[65] = { 0 };
	char MesHex[16] = { 0 };         // 16���ַ��������ڴ�� 64λ16���Ƶ�����
	char MyKey[8] = { 0 };           // ��ʼ��Կ 8�ֽ�*8
	char MyMessage[8] = { 0 };       // ��ʼ���� 


	printf("���������Ϣ(64 bit):\n");
	gets(MyMessage);            // ����
	printf("����8λ��Կ:\n");
	gets(MyKey);                // ��Կ

	while (MyKey[i] != '\0'){   // ������Կ����
		i++;
	}
	while (i != 8){ // ����8 ��ʾ����
		printf("��Կ���ȴ���!\n");
		gets(MyKey);
		i = 0;
		while (MyKey[i] != '\0'){ // �ٴμ��
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
		printf("1:��ַ��� \n2:��Կ�������\n3:���Ĳ������\n0:exit\n");
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