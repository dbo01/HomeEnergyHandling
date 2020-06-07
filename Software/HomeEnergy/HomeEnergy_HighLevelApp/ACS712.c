#include <stdint.h>

double maxCurr;
double MinCurr;

double toAmpsACS712(uint32_t RegVal )
{
	//double res = (double)(2.5F * (1 - (RegVal / 4096.0F))) / 0.066F;
	double res = (((double)RegVal * 2.5 / 4095) - 2.485) / 0.136;
	if (res < 0) res = -res;
	return (double)res;
}