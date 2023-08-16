#include <cmath>
#include <limits>
#include <sstream>
#include <string>

#include "integer.h"

using namespace std;

namespace alfc {

Integer::Integer(const std::string& s, unsigned base)
  : d_value(s, base)
{}

Integer& Integer::operator=(const Integer& x)
{
  if (this == &x) return *this;
  d_value = x.d_value;
  return *this;
}

bool Integer::operator==(const Integer& y) const
{
  return d_value == y.d_value;
}

bool Integer::operator>(const Integer& y) const { return d_value > y.d_value; }

bool Integer::operator>=(const Integer& y) const { return d_value >= y.d_value; }

Integer Integer::operator-() const { return Integer(-(d_value)); }

Integer Integer::operator+(const Integer& y) const
{
  return Integer(d_value + y.d_value);
}

Integer Integer::operator*(const Integer& y) const
{
  return Integer(d_value * y.d_value);
}

Integer Integer::bitwiseOr(const Integer& y) const
{
  mpz_class result;
  mpz_ior(result.get_mpz_t(), d_value.get_mpz_t(), y.d_value.get_mpz_t());
  return Integer(result);
}

Integer Integer::bitwiseAnd(const Integer& y) const
{
  mpz_class result;
  mpz_and(result.get_mpz_t(), d_value.get_mpz_t(), y.d_value.get_mpz_t());
  return Integer(result);
}

Integer Integer::bitwiseXor(const Integer& y) const
{
  mpz_class result;
  mpz_xor(result.get_mpz_t(), d_value.get_mpz_t(), y.d_value.get_mpz_t());
  return Integer(result);
}

Integer Integer::bitwiseNot() const
{
  mpz_class result;
  mpz_com(result.get_mpz_t(), d_value.get_mpz_t());
  return Integer(result);
}

Integer Integer::multiplyByPow2(uint32_t pow) const
{
  mpz_class result;
  mpz_mul_2exp(result.get_mpz_t(), d_value.get_mpz_t(), pow);
  return Integer(result);
}

void Integer::setBit(uint32_t i, bool value)
{
  if (value)
  {
    mpz_setbit(d_value.get_mpz_t(), i);
  }
  else
  {
    mpz_clrbit(d_value.get_mpz_t(), i);
  }
}

bool Integer::isBitSet(uint32_t i) const
{
  return extractBitRange(1, i).sgn()!=0;
}

Integer Integer::oneExtend(uint32_t size, uint32_t amount) const
{
  // check that the size is accurate
  //Assert((*this) < Integer(1).multiplyByPow2(size));
  mpz_class res = d_value;

  for (unsigned i = size; i < size + amount; ++i)
  {
    mpz_setbit(res.get_mpz_t(), i);
  }

  return Integer(res);
}

uint32_t Integer::toUnsignedInt() const
{
  return mpz_get_ui(d_value.get_mpz_t());
}

Integer Integer::extractBitRange(uint32_t bitCount, uint32_t low) const
{
  // bitCount = high-low+1
  uint32_t high = low + bitCount - 1;
  //- Function: void mpz_fdiv_r_2exp (mpz_t r, mpz_t n, mp_bitcnt_t b)
  mpz_class rem, div;
  mpz_fdiv_r_2exp(rem.get_mpz_t(), d_value.get_mpz_t(), high + 1);
  mpz_fdiv_q_2exp(div.get_mpz_t(), rem.get_mpz_t(), low);

  return Integer(div);
}

Integer Integer::floorDivideQuotient(const Integer& y) const
{
  mpz_class q;
  mpz_fdiv_q(q.get_mpz_t(), d_value.get_mpz_t(), y.d_value.get_mpz_t());
  return Integer(q);
}

Integer Integer::floorDivideRemainder(const Integer& y) const
{
  mpz_class r;
  mpz_fdiv_r(r.get_mpz_t(), d_value.get_mpz_t(), y.d_value.get_mpz_t());
  return Integer(r);
}

void Integer::floorQR(Integer& q,
                      Integer& r,
                      const Integer& x,
                      const Integer& y)
{
  mpz_fdiv_qr(q.d_value.get_mpz_t(),
              r.d_value.get_mpz_t(),
              x.d_value.get_mpz_t(),
              y.d_value.get_mpz_t());
}

Integer Integer::ceilingDivideQuotient(const Integer& y) const
{
  mpz_class q;
  mpz_cdiv_q(q.get_mpz_t(), d_value.get_mpz_t(), y.d_value.get_mpz_t());
  return Integer(q);
}

Integer Integer::ceilingDivideRemainder(const Integer& y) const
{
  mpz_class r;
  mpz_cdiv_r(r.get_mpz_t(), d_value.get_mpz_t(), y.d_value.get_mpz_t());
  return Integer(r);
}

void Integer::euclidianQR(Integer& q,
                          Integer& r,
                          const Integer& x,
                          const Integer& y)
{
  // compute the floor and then fix the value up if needed.
  floorQR(q, r, x, y);

  if (r.sgn()<0)
  {
    // if r < 0
    // abs(r) < abs(y)
    // - abs(y) < r < 0, then 0 < r + abs(y) < abs(y)
    // n = y * q + r
    // n = y * q - abs(y) + r + abs(y)
    if (r.sgn() >= 0)
    {
      // y = abs(y)
      // n = y * q - y + r + y
      // n = y * (q-1) + (r+y)
      q = q+(-Integer(1));
      r = r+y;
    }
    else
    {
      // y = -abs(y)
      // n = y * q + y + r - y
      // n = y * (q+1) + (r-y)
      q = q+Integer(1);
      r = r+(-y);
    }
  }
}

Integer Integer::euclidianDivideQuotient(const Integer& y) const
{
  Integer q, r;
  euclidianQR(q, r, *this, y);
  return q;
}

Integer Integer::euclidianDivideRemainder(const Integer& y) const
{
  Integer q, r;
  euclidianQR(q, r, *this, y);
  return r;
}

Integer Integer::exactQuotient(const Integer& y) const
{
  //Assert(y.divides(*this));
  mpz_class q;
  mpz_divexact(q.get_mpz_t(), d_value.get_mpz_t(), y.d_value.get_mpz_t());
  return Integer(q);
}

Integer Integer::modByPow2(uint32_t exp) const
{
  mpz_class res;
  mpz_fdiv_r_2exp(res.get_mpz_t(), d_value.get_mpz_t(), exp);
  return Integer(res);
}

Integer Integer::divByPow2(uint32_t exp) const
{
  mpz_class res;
  mpz_fdiv_q_2exp(res.get_mpz_t(), d_value.get_mpz_t(), exp);
  return Integer(res);
}

int Integer::sgn() const { return mpz_sgn(d_value.get_mpz_t()); }

Integer Integer::pow(uint32_t exp) const
{
  mpz_class result;
  mpz_pow_ui(result.get_mpz_t(), d_value.get_mpz_t(), exp);
  return Integer(result);
}

Integer Integer::modAdd(const Integer& y, const Integer& m) const
{
  mpz_class res;
  mpz_add(res.get_mpz_t(), d_value.get_mpz_t(), y.d_value.get_mpz_t());
  mpz_mod(res.get_mpz_t(), res.get_mpz_t(), m.d_value.get_mpz_t());
  return Integer(res);
}

Integer Integer::modMultiply(const Integer& y, const Integer& m) const
{
  mpz_class res;
  mpz_mul(res.get_mpz_t(), d_value.get_mpz_t(), y.d_value.get_mpz_t());
  mpz_mod(res.get_mpz_t(), res.get_mpz_t(), m.d_value.get_mpz_t());
  return Integer(res);
}

Integer Integer::modInverse(const Integer& m) const
{
  //Assert(m > 0) << "m must be greater than zero";
  mpz_class res;
  if (mpz_invert(res.get_mpz_t(), d_value.get_mpz_t(), m.d_value.get_mpz_t())
      == 0)
  {
    return Integer(-1);
  }
  return Integer(res);
}

bool Integer::divides(const Integer& y) const
{
  int res = mpz_divisible_p(y.d_value.get_mpz_t(), d_value.get_mpz_t());
  return res != 0;
}

std::string Integer::toString(int base) const { return d_value.get_str(base); }

bool Integer::testBit(unsigned n) const
{
  return mpz_tstbit(d_value.get_mpz_t(), n);
}

unsigned Integer::isPow2() const
{
  if (d_value <= 0) return 0;
  // check that the number of ones in the binary representation is 1
  if (mpz_popcount(d_value.get_mpz_t()) == 1)
  {
    // return the index of the first one plus 1
    return mpz_scan1(d_value.get_mpz_t(), 0) + 1;
  }
  return 0;
}

size_t Integer::length() const
{
  if (sgn() == 0)
  {
    return 1;
  }
  else
  {
    return mpz_sizeinbase(d_value.get_mpz_t(), 2);
  }
}

}  // namespace cvc5::internal
