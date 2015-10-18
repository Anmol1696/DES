# include <iostream>
# include <cstdlib>
# include <string>
# include <vector>
# include <cmath>
# include <bitset>
# include <algorithm>
# include "des.h"

using namespace std;

conversion::conversion()
{
	head=NULL;
	temp=NULL;
	cur=NULL;
	key_head=NULL;
}

void conversion::text_binary(string input)
{

	for(int t=0;t<input.size();t+=8)
	{
		node* n = new node;
		for(int j=0;j<8;j++)
		{
			for(int i=7;i>=0;--i)
			{
				int q=0;
				if((input[j+t]>>i)%2==1) q=1;
				n->data.push_back(q);
			}
		}

		n->next=NULL;
		if(head != NULL)
		{
			  cur=head;
			  while(cur->next != NULL)
				cur=cur->next;
			  cur->next=n;
		}
		else head = n;
	}
}

void conversion::encrypted_binary(string input)
{
	for(int t=0;t<input.size();t+=11)
	{
		node* n = new node;
		for(int j=0;j<11;j++)
		{
			for(int i=5;i>=0;--i)
			{
				int q=0;
				if(((input[j+t]-32)>>i)%2==1) q=1;
				n->data.push_back(q);
			}
		}

		n->data.erase(n->data.begin()+64,n->data.end());

		n->next=NULL;
		if(head != NULL)
		{
			cur=head;
			while(cur->next != NULL)
			    cur=cur->next;
			cur->next=n;
		}
		else head = n;
	}
}


void conversion::key_binary(string key)
{
	for(int j=0;j<7;j++)
	{
		for(int i=7;i>=0;--i)
		{
			int q=0;
			if(j<key.size() &&(key[j]>>i)%2==1) q=1;
			B_key.push_back(q);
		}
	}
}

void conversion::IP1()
{
	cur = head;
	int per_1[64]={57,49,41,33,25,17,9,1,
		       59,51,43,35,27,19,11,3,
		       61,53,45,37,29,21,13,5,
		       63,55,47,39,31,23,15,7,
		       56,48,40,32,24,16,8,0,
		       58,50,42,34,26,18,10,2,
		       60,52,44,36,28,20,12,4,
		       62,54,46,38,30,22,14,6};
	while(cur->data.size()>0)
	{
		vector <int> vec;
		for(int i=0;i<64;i++)	vec.push_back(cur->data[per_1[i]]);

		for(int i=0;i<64;i++)	cur->data[i]=vec[i];

		if(cur->next==NULL) break;
		else cur=cur->next;
	}
}

void conversion::IP2()
{
	cur = head;

	int per[64] = {39,7,47,15,55,23,63,31,
		       38,6,46,14,54,22,62,30,
		       37,5,45,13,53,21,61,29,
		       36,4,44,12,52,20,60,28,
		       35,3,43,11,51,19,59,27,
		       34,2,42,10,50,18,58,26,
		       33,1,41,9,49,17,57,25,
		       32,0,40,8,48,16,56,24};

	while(cur->data.size()>0)
	{
		vector <int> vec;

		for(int i=0;i<64;i++)	vec.push_back(cur->data[per[i]]);

		for(int i=0;i<64;i++)	cur->data[i]=vec[i];

		if(cur->next==NULL) break;
		else cur=cur->next;
	}
}

void conversion::PC1()							// PC1 is not working with PC2
{												// both are working seperatelly
	int table[56] ={57,49,41,33,25,17,9,
			1,58,50,42,34,26,18,
			10,2,59,51,43,35,27,
			19,11,3,60,52,44,36,
			63,55,47,39,31,23,15,
			7,62,54,46,38,30,22,
			14,6,61,53,45,37,29,
			21,13,5,28,20,12,4};
	vector <int> L;

	for(int i=0;i<56;i++)	L.push_back(B_key[(table[i]-(table[i]/8))-1]);
	for(int i=0;i<56;i++)	B_key[i]=L[i];
}



void conversion::PC2_con()
{
	key_node* a;
	a=key_head;

	vector <int> vec;
	int per[48] =  {13,16,10,23,0,4,
			2,27,14,5,20,9,
			22,18,11,3,25,7,
			15,6,26,19,12,1,
			40,51,30,36,46,54,
			29,39,50,44,32,47,
			43,48,38,55,33,52,
			45,41,49,35,28,31};

	while(a->next!=NULL)
	{
		for(int y=0;y<48;y++)	vec.push_back(a->rkey[y]);

		for(int i=0;i<48;i++)
		{
			a->rkey[i]=vec[i];
			a->rkey.erase (a->rkey.begin()+48,a->rkey.end());
		}

		a=a->next;
		vec.erase(vec.begin(),vec.end());
	}

	for(int y=0;y<48;y++)	vec.push_back(a->rkey[y]);

	for(int i=0;i<48;i++)
	{
		a->rkey[i]=vec[i];
		a->rkey.erase (a->rkey.begin()+48,a->rkey.end());
	}
}



void conversion::PC2()
{
	vector <int> C;
	vector <int> D;

	for(int i=0;i<28;i++)
	{
		C.push_back(B_key[i]);
		D.push_back(B_key[28+i]);
	}

	key_node* keytemp;
	key_node* n;
	for(int r=0;r<16;r++)
	{
		n=new key_node;
		if(r==0 || r==1 || r==8 || r==15)
		{
			C.push_back(0);
			C.erase(C.begin()+0);
			D.push_back(0);
			D.erase(D.begin()+0);
		}

		else if(r!=0 && r!=1 && r!=8 && r!=15)
		{
			C.push_back(0);
			C.erase(C.begin()+0);
			C.push_back(0);
			C.erase(C.begin()+0);
			D.push_back(0);
			D.erase(D.begin()+0);
			D.push_back(0);
			D.erase(D.begin()+0);
		}

		n->rkey.reserve(C.size()+D.size());  // preallocate memory
		n->rkey.insert(n->rkey.end(),C.begin(),C.end());
		n->rkey.insert(n->rkey.end(),D.begin(),D.end());
		n->next=NULL;

		keytemp=key_head;
		if(key_head!=NULL)
		{
			while(keytemp->next!=NULL)   keytemp=keytemp->next;
			keytemp->next=n;
		}
		else	key_head=n;
	}
}

void conversion::S(vector <int> &R)															//  Working good .................................
{
	vector <int> R1;
	vector <int> R2;
	vector <int> R3;
	vector <int> R4;
	vector <int> R5;
	vector <int> R6;
	vector <int> R7;
	vector <int> R8;

	for(int i=0;i<6;i++)
	{
		R1.push_back(R[i]);
		R2.push_back(R[i+6]);
		R3.push_back(R[i+12]);
		R4.push_back(R[i+18]);
		R5.push_back(R[i+24]);
		R6.push_back(R[i+30]);
		R7.push_back(R[i+36]);
		R8.push_back(R[i+42]);
	}

	struct box
	{
		vector <int> bin;
		int index;
		box* next;
	};
	box* box_head=NULL;
	box* box_temp=NULL;

	box_head=new box;
	box_head->index=0;

	for(int y=0;y<4;y++)	box_head->bin.push_back(0);
	box_temp=box_head;

	box* n1=new box;
	n1->index=1;
	n1->bin.push_back(0);
	n1->bin.push_back(0);
	n1->bin.push_back(0);
	n1->bin.push_back(1);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=2;
	n1->bin.push_back(0);
	n1->bin.push_back(0);
	n1->bin.push_back(1);
	n1->bin.push_back(0);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=3;
	n1->bin.push_back(0);
	n1->bin.push_back(0);
	n1->bin.push_back(1);
	n1->bin.push_back(1);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=4;
	n1->bin.push_back(0);
	n1->bin.push_back(1);
	n1->bin.push_back(0);
	n1->bin.push_back(0);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=5;
	n1->bin.push_back(0);
	n1->bin.push_back(1);
	n1->bin.push_back(0);
	n1->bin.push_back(1);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=6;
	n1->bin.push_back(0);
	n1->bin.push_back(1);
	n1->bin.push_back(1);
	n1->bin.push_back(0);
	box_temp->next=n1;
	box_temp=box_temp->next;

        n1=new box;
	n1->index=7;
	n1->bin.push_back(0);
	n1->bin.push_back(1);
	n1->bin.push_back(1);
	n1->bin.push_back(1);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=8;
	n1->bin.push_back(1);
	n1->bin.push_back(0);
	n1->bin.push_back(0);
	n1->bin.push_back(0);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=9;
	n1->bin.push_back(1);
	n1->bin.push_back(0);
	n1->bin.push_back(0);
	n1->bin.push_back(1);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=10;
	n1->bin.push_back(1);
	n1->bin.push_back(0);
	n1->bin.push_back(1);
	n1->bin.push_back(0);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=11;
	n1->bin.push_back(1);
	n1->bin.push_back(0);
	n1->bin.push_back(1);
	n1->bin.push_back(1);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=12;
	n1->bin.push_back(1);
	n1->bin.push_back(1);
	n1->bin.push_back(0);
	n1->bin.push_back(0);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=13;
	n1->bin.push_back(1);
	n1->bin.push_back(1);
	n1->bin.push_back(0);
	n1->bin.push_back(1);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=14;
	n1->bin.push_back(1);
	n1->bin.push_back(1);
	n1->bin.push_back(1);
	n1->bin.push_back(0);
	box_temp->next=n1;
	box_temp=box_temp->next;

	n1=new box;
	n1->index=15;
	n1->bin.push_back(1);
	n1->bin.push_back(1);
	n1->bin.push_back(1);
	n1->bin.push_back(1);
	box_temp->next=n1;

	box_temp=box_head;
	for(int t=0;t<16;t++)
	{
		if(R1[2]==box_temp->bin[0] && R1[3]==box_temp->bin[1] && R1[4]==box_temp->bin[2] && R1[5]==box_temp->bin[3])
		break;
		else
		box_temp=box_temp->next;
	}

	int S1[4][16]={{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
			{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
			{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
			{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}};

	int S2[4][16]={{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
	               {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
	               {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
	               {13,8,10,1,3,15,4,2,11,6,7,15,0,5,14,9}};

	int S3[4][16]={{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
	               {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
	               {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
	               {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}};

	int S4[4][16]={{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
			{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
			{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
			{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}};

	int S5[4][16]={{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
	               {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
	               {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
	               {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}};

	int S6[4][16]={{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
	               {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
	               {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
	               {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}};

	int S7[4][16]={{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
	               {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
	               {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
	               {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}};

	int S8[4][16]={{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
	               {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
	               {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
	               {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}};


	int row[8];

	if(R1[0]==0&&R1[1]==0) row[0]=0;
	else if(R1[0]==0&&R1[1]==1) row[0]=1;
	else if(R1[0]==1&&R1[1]==0) row[0]=2;
	else if(R1[0]==1&&R1[1]==1) row[0]=3;

        box* cur=box_head;
	while(cur->index!=S1[row[0]][box_temp->index]) cur = cur->next;
	for(int i=0;i<R1.size();i++)  R1[i]=cur->bin[i];
	R1.erase(R1.begin()+4,R1.end());

	if(R2[0]==0&&R2[1]==0) row[1]=0;
	else if(R2[0]==0&&R2[1]==1) row[1]=1;
	else if(R2[0]==1&&R2[1]==0) row[1]=2;
	else if(R2[0]==1&&R2[1]==1) row[1]=3;

	cur=box_head;
	while(cur->index!=S2[row[1]][box_temp->index]) cur = cur->next;
	for(int i=0;i<R2.size();i++)  R2[i]=cur->bin[i];
	R2.erase(R2.begin()+4,R2.end());

	if(R3[0]==0&&R3[1]==0) row[2]=0;
	else if(R3[0]==0&&R3[1]==1) row[2]=1;
	else if(R3[0]==1&&R3[1]==0) row[2]=2;
	else if(R3[0]==1&&R3[1]==1) row[2]=3;

	cur=box_head;
	while(cur->index!=S3[row[2]][box_temp->index]) cur = cur->next;
	for(int i=0;i<R3.size();i++)  R3[i]=cur->bin[i];
	R3.erase(R3.begin()+4,R3.end());

	if(R4[0]==0&&R4[1]==0) row[3]=0;
	else if(R4[0]==0&&R4[1]==1) row[3]=1;
	else if(R4[0]==1&&R4[1]==0) row[3]=2;
	else if(R4[0]==1&&R4[1]==1) row[3]=3;

	cur=box_head;
	while(cur->index!=S4[row[3]][box_temp->index]) cur = cur->next;
	for(int i=0;i<R4.size();i++)  R4[i]=cur->bin[i];
	R4.erase(R4.begin()+4,R4.end());

	if(R5[0]==0&&R5[1]==0) row[4]=0;
	else if(R5[0]==0&&R5[1]==1) row[4]=1;
	else if(R5[0]==1&&R5[1]==0) row[4]=2;
	else if(R5[0]==1&&R5[1]==1) row[4]=3;

	cur=box_head;
	while(cur->index!=S5[row[4]][box_temp->index]) cur = cur->next;
	for(int i=0;i<R5.size();i++)  R5[i]=cur->bin[i];
	R5.erase(R5.begin()+4,R5.end());

	if(R6[0]==0&&R6[1]==0) row[5]=0;
	else if(R6[0]==0&&R6[1]==1) row[5]=1;
	else if(R6[0]==1&&R6[1]==0) row[5]=2;
	else if(R6[0]==1&&R6[1]==1) row[5]=3;

	cur=box_head;
	while(cur->index!=S6[row[5]][box_temp->index]) cur = cur->next;
	for(int i=0;i<R6.size();i++)  R6[i]=cur->bin[i];
	R6.erase(R6.begin()+4,R6.end());

	if(R7[0]==0&&R7[1]==0) row[6]=0;
	else if(R7[0]==0&&R7[1]==1) row[6]=1;
	else if(R7[0]==1&&R7[1]==0) row[6]=2;
	else if(R7[0]==1&&R7[1]==1) row[6]=3;

	cur=box_head;
	while(cur->index!=S7[row[0]][box_temp->index]) cur = cur->next;
	for(int i=0;i<R7.size();i++)  R7[i]=cur->bin[i];
	R7.erase(R7.begin()+4,R7.end());

	if(R8[0]==0&&R8[1]==0) row[7]=0;
	else if(R8[0]==0&&R8[1]==1) row[7]=1;
	else if(R8[0]==1&&R8[1]==0) row[7]=2;
	else if(R8[0]==1&&R8[1]==1) row[7]=3;

	cur=box_head;
	while(cur->index!=S8[row[7]][box_temp->index]) cur = cur->next;
	for(int i=0;i<R8.size();i++)  R8[i]=cur->bin[i];
	R8.erase(R8.begin()+4,R8.end());

	for(int u=0;u<4;u++)
	{
		R[u]=R1[u];
		R[u+4]=R2[u];
		R[u+8]=R3[u];
		R[u+12]=R4[u];
		R[u+16]=R5[u];
		R[u+20]=R6[u];
		R[u+24]=R7[u];
		R[u+28]=R8[u];
	}

	R.erase(R.begin()+32,R.end());

}


void conversion::E()
{

	key_node* tempcur;
	temp = head;
	vector <int> R;
	vector <int> L;

	int per[48]= {32,1,2,3,4,5,
		      4,5,6,7,8,9,
		      8,9,10,11,12,13,
		      12,13,14,15,16,17,
		      16,17,18,19,20,21,
		      20,21,22,23,24,25,
		      24,25,26,27,28,29,
		      28,29,30,31,32,1};

	while(temp->next!=NULL)
	{
		tempcur = key_head;
		for(int j=0;j<32;j++)
		{
			L.push_back(temp->data[j]);
			R.push_back(temp->data[32+j]);
		}

		for(int i=0;i<16;i++)
		{
			vector <int> vec;
			for(int y=0;y<32;y++) vec.push_back(L[y]);
			for(int y=0;y<32;y++) L[y]=R[y];
			for(int o=0;o<32;o++) R[o]=R[per[o]-1];
			for(int y=32;y<48;y++) R.push_back(R[per[y]-1]);
			for(int o=0;o<R.size();o++) R[o]=R[o]^tempcur->rkey[o];
			S(R);
			for(int y=0;y<32;y++) R[y]=vec[y]^R[y];
			tempcur=tempcur->next;
			for(int t=0;t<32;t++) temp->data[t]=L[t];
			for(int t=0;t<32;t++) temp->data[t+32]=R[t];
		}
		temp=temp->next;
		L.erase(L.begin(),L.end());
		R.erase(R.begin(),R.end());
	}

	tempcur = key_head;
	for(int j=0;j<32;j++)
	{
		L.push_back(temp->data[j]);
		R.push_back(temp->data[32+j]);
	}

	for(int i=0;i<16;i++)
	{
		vector <int> vec;
		for(int y=0;y<32;y++) vec.push_back(L[y]);
		for(int y=0;y<32;y++) L[y]=R[y];
		for(int o=0;o<32;o++) R[o]=R[per[o]-1];
		for(int y=32;y<48;y++) R.push_back(R[per[y]-1]);
		for(int o=0;o<R.size();o++) R[o]=R[o]^tempcur->rkey[o];
		S(R);
		for(int y=0;y<32;y++) R[y]=vec[y]^R[y];
		tempcur=tempcur->next;
		for(int t=0;t<32;t++) temp->data[t]=L[t];
		for(int t=0;t<32;t++) temp->data[t+32]=R[t];
	}
	L.erase(L.begin(),L.end());
	R.erase(R.begin(),R.end());
}

void conversion::swap_key()
{
	key_node* tempfor;
	tempfor = key_head;
	vector <int> vec1;
	vector <int> vec2;

	for(int i=0;i<8;i++)
	{
		for(int a=0;a<i;a++)	tempfor=tempfor->next;
		for(int y=0;y<48;y++)	vec1.push_back(tempfor->rkey[y]);
		tempfor=key_head;
		for(int a=15;a>i;a--)	tempfor=tempfor->next;

		for(int y=0;y<48;y++)	vec2.push_back(tempfor->rkey[y]);
		tempfor=key_head;
		for(int a=0;a<i;a++)	tempfor=tempfor->next;

		for(int y=0;y<48;y++)	tempfor->rkey[y]=vec2[y];
		tempfor=key_head;
		for(int a=15;a>i;a--)	tempfor=tempfor->next;
		for(int y=0;y<48;y++)	tempfor->rkey[y]=vec1[y];
		tempfor=key_head;
		vec1.erase(vec1.begin(),vec1.end());
		vec2.erase(vec2.begin(),vec2.end());
	}
}

void conversion::D()
{
	key_node* tempcur;
	temp = head;
	vector <int> R;
	vector <int> L;

	int per[48]    =   {32,1,2,3,4,5,
			    4,5,6,7,8,9,
			    8,9,10,11,12,13,
			    12,13,14,15,16,17,
			    16,17,18,19,20,21,
			    20,21,22,23,24,25,
			    24,25,26,27,28,29,
			    28,29,30,31,32,1};

	while(temp->next!=NULL)
	{
		tempcur = key_head;
		for(int j=0;j<32;j++)
		{
			L.push_back(temp->data[j]);
			R.push_back(temp->data[32+j]);
		}

		for(int i=0;i<16;i++)
		{
			vector <int> vec;
			for(int y=0;y<32;y++) vec.push_back(R[y]);
			for(int y=0;y<32;y++) R[y]=L[y];
			for(int o=0;o<32;o++) L[o]=L[per[o]-1];
			for(int y=32;y<48;y++) L.push_back(L[per[y]-1]);
			for(int o=0;o<L.size();o++) L[o]=L[o]^tempcur->rkey[o];
			S(L);
			for(int y=0;y<32;y++) L[y]=vec[y]^L[y];
			tempcur=tempcur->next;

			for(int t=0;t<32;t++) temp->data[t]=L[t];
			for(int t=0;t<32;t++) temp->data[t+32]=R[t];
		}
		temp=temp->next;
		L.erase(L.begin(),L.end());
		R.erase(R.begin(),R.end());
	}

	tempcur = key_head;
	for(int j=0;j<32;j++)
	{
		L.push_back(temp->data[j]);
		R.push_back(temp->data[32+j]);
	}

	for(int i=0;i<16;i++)
	{
		vector <int> vec;
		for(int y=0;y<32;y++) vec.push_back(R[y]);
		for(int y=0;y<32;y++) R[y]=L[y];
		for(int o=0;o<32;o++) L[o]=L[per[o]-1];
		for(int y=32;y<48;y++) L.push_back(L[per[y]-1]);
		for(int o=0;o<L.size();o++) L[o]=L[o]^tempcur->rkey[o];
		S(L);
		for(int y=0;y<32;y++) L[y]=vec[y]^L[y];
		tempcur=tempcur->next;

		for(int t=0;t<32;t++) temp->data[t]=L[t];
		for(int t=0;t<32;t++) temp->data[t+32]=R[t];
	}
	L.erase(L.begin(),L.end());
	R.erase(R.begin(),R.end());
}

void conversion::binary_6()
{
	cur=head;
	while(cur->next!=NULL)
	{
		cur->data.push_back(0);
		cur->data.push_back(0);
		cur=cur->next;
	}
	cur->data.push_back(0);
	cur->data.push_back(0);
	cur=head;

	while(cur->next!=NULL)
	{
		for(int i=0;i<cur->data.size();i+=6)
		{
			char output;
			int tem=0;
			for(int u=0;u<6;u++)	tem+=(pow(2,5-u)*cur->data[u+i]);
			output=tem+32;
			EncryptedText.push_back(output);
		}
		cur=cur->next;
	}

	for(int i=0;i<cur->data.size();i+=6)
	{
		char output;
		int tem=0;
		for(int u=0;u<6;u++)	tem+=(pow(2,5-u)*cur->data[u+i]);
		output=tem+32;
		EncryptedText.push_back(output);
	}
	cur=cur->next;

}

void conversion::print_EncryptedText()
{
	 for(int i=0;i<EncryptedText.size();i++)	cout << EncryptedText[i];

	 cout << endl;
}

void conversion::print_DecryptedText()
{
	cur=head;

	while(cur->next!=NULL)
	{
		for(int i=0;i<cur->data.size();i+=8)
		{
			char output;
			int tem=0;
			for(int u=0;u<8;u++)	tem+=(pow(2,7-u)*cur->data[u+i]);
			output=tem;
			EncryptedText.push_back(output);
		}
		cur=cur->next;
	}

	for(int i=0;i<cur->data.size();i+=8)
	{
		char output;
		int tem=0;
		for(int u=0;u<8;u++)	tem+=(pow(2,7-u)*cur->data[u+i]);
		output=tem;
		EncryptedText.push_back(output);
	}

	for(int i=0;i<EncryptedText.size();i++)	cout << EncryptedText[i];
	cout << endl;

}
