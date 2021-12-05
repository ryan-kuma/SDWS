#include "cryptopp/integer.h"
#include "cryptopp/osrng.h"

#include <iostream>
#include <vector>
#include <utility>


using namespace std;
using namespace CryptoPP;

static Integer maxp("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

Integer calculate_Y(int x, vector<Integer> &poly)
{
	Integer y("0");
	Integer temp("1");
	for (auto coeff : poly) {
		y = (y + (coeff * temp));
		temp = (temp * x);
	}
	
	y = y % maxp;
	return y;
}

void secret_sharing(Integer S, vector<Integer> &points, int N, int K)
{
	vector<Integer> poly(K);	
	poly[0] = S;
	AutoSeededRandomPool prng;
	
	for (int i = 1; i < K; ++i)
	{
		Integer p(prng, Integer::One(), maxp);
		poly[i] = p;
	}

	for (int i = 1; i <= N; i++)
	{
		Integer y = calculate_Y(i, poly);
		points[i-1] = y;
	}
}

Integer generateSecret(int* x, vector<Integer> &y, int M)
{
	Integer ans = Integer::Zero();
	Integer ans_dens = Integer::One();
	for (int i = 0; i < M; i++)
	{
		Integer l = y[i];
		Integer l_dens = Integer::One();
		for (int j = 0; j < M; j++)
		{
			if (j == i)
				continue;
			l = l * x[j];
			l_dens = l_dens * (x[i]-x[j]);
		}
		ans = ans * l_dens - l * ans_dens;
		ans_dens = ans_dens * l_dens;
	}

	ans = ans / ans_dens;
	ans = ans % maxp;
	return ans;
}

int main()
{
	AutoSeededRandomPool prng;
	Integer S(prng, Integer::One(), maxp);
	Integer b(prng, Integer::One(), maxp);

	int N = 100;
	int K = 20;
	cout<<"start="<<S*b%maxp<<endl;
	cout<<"------------------------------------"<<endl;

	vector<Integer> points(N);
	secret_sharing(S, points, N, K);
	for (int i = 0; i < N; i++)
	{
		cout<<"points"<<i<<"=   "<<points[i]<<endl;
		points[i] = points[i] * b % maxp;
	}
	
	int x[K]; 
	for (int i = 1; i <= K; i++)
		x[i-1] = i;
	Integer res = generateSecret(&x[0], points, K);

	cout<<"res="<<res<<endl;

	return 0;
}
