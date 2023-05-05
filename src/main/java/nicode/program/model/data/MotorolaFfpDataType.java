/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nicode.program.model.data;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeEncodeException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.mem.MemBuffer;

/**
 * Provides a built-in data type for Motorola Fast Floating Point (MFFP)
 *
 * Big-endian 32-bit base-10 floating point number with 24-bit significand (MSB stored),
 * 1-bit sign, and 7-bit exponent with a bias of 65 (in this order from MSB to LSB).
 * Neither negative zero, nor quiet/signaling NaN, nor Infinity, nor subnormal values.
 */
public class MotorolaFfpDataType extends BuiltIn {

	private static final int BYTE_SIZE = 4; // Size of encoded Motorola FFP in bytes
	private static final int EXPONENT_POS = 0; // Lowest bit position of encoded exponent
	private static final int EXPONENT_SIZE = 7; // Number of bits in encoded exponent
	private static final int EXPONENT_MASK = (1 << EXPONENT_SIZE) - 1; // 0x7F
	private static final int MAX_EXPONENT = EXPONENT_MASK; // Maximum encoded exponent
	private static final int MIN_EXPONENT = 0; // Minimum encoded exponent
	private static final int EXPONENT_BIAS = 65; // Distance from biased to encoded exponent
	private static final int MAX_SCALE = MAX_EXPONENT - EXPONENT_BIAS; // Maximum biased exponent
	private static final int MIN_SCALE = MIN_EXPONENT - EXPONENT_BIAS; // Minimum biased exponent
	private static final int SIGN_POS = 7; // Bit position of sign bit
	private static final int FRACTION_POS = 8; // Lowest bit position of encoded fraction
	private static final int FRACTION_SIZE = 23; // Number of bits in encoded fraction
	private static final int FRACTION_MASK = (1 << FRACTION_SIZE) - 1; // 0x7FFFFF
	private static final int MAX_FRACTION = FRACTION_MASK; // Maximum encoded fraction
	private static final int SIGNIFICAND_MSB = 1 << FRACTION_SIZE; // Non-zero significand MSB = 1
	private static final int SIGNIFICAND_POS = FRACTION_POS; // Lowest bit position of significand
	private static final int SIGNIFICAND_MASK = SIGNIFICAND_MSB | FRACTION_MASK; // 0xFFFFFF

	/**
	 * A constant holding the largest negative encoded value (0xFFFFFFFF = -9.2233714E+18)
	 */
	public static final int MAX_NEGATIVE_VALUE = encodeMotorolaFfp(true, MAX_FRACTION, MAX_SCALE);
	/**
	 * A constant holding the largest positive encoded value (0xFFFFFF7F = +9.2233714E+18)
	 */
	public static final int MAX_POSITIVE_VALUE = encodeMotorolaFfp(false, MAX_FRACTION, MAX_SCALE);
	/**
	 * A constant holding the smallest negative encoded value (0x80000080 = -2.7105054E-20)
	 */
	public static final int MIN_NEGATIVE_VALUE = encodeMotorolaFfp(true, 0, MIN_SCALE);
	/**
	 * A constant holding the smallest positive encoded value (0x80000100 = +2.7105058E-20)
	 */
	public static final int MIN_POSITIVE_VALUE = encodeMotorolaFfp(false, 1, MIN_SCALE);
	/**
	 * A constant holding the encoded zero value (always positive, there is no negative zero)
	 */
	public static final int ZERO_VALUE = encodeMotorolaFfp(false, 0, -EXPONENT_BIAS);
	
	public MotorolaFfpDataType() {
		this(null);
	}

	public MotorolaFfpDataType(DataTypeManager dtm) {
		super(null, "MotorolaFFP", dtm);
	}

	private static int extractExponentCode(int encodedValue) {
		return (encodedValue >>> EXPONENT_POS) & EXPONENT_MASK;
	}

	private static int extractSignBit(int encodedValue) {
		return (encodedValue >>> SIGN_POS) & 1;
	}

	private static int extractSignificandCode(int encodedValue) {
		return (encodedValue >>> SIGNIFICAND_POS) & SIGNIFICAND_MASK;
	}

	private static int encodeMotorolaFfp(boolean sign, int fraction, int scale) {
		int fractionCode = fraction & FRACTION_MASK;
		int exponentCode = scale + EXPONENT_BIAS;

		// Original library IEEE 754 binary32 to Motorola FFP conversion rules
		if (exponentCode == 0 && !sign && fractionCode == 0) {
			return ZERO_VALUE;
		}
		if (exponentCode < MIN_EXPONENT) {
			return ZERO_VALUE;
		}
		if (exponentCode > MAX_EXPONENT) {
			return sign ? MAX_NEGATIVE_VALUE : MAX_POSITIVE_VALUE;
		}

		int encodedValue = exponentCode << EXPONENT_POS;
		if (sign) {
			encodedValue |= 1 << SIGN_POS;
		}
		encodedValue |= (SIGNIFICAND_MSB | fractionCode) << SIGNIFICAND_POS;
		return encodedValue;
	}

	/**
	 * Convert encoded Motorola Fast Floating Point (MFFP) value into host's float
	 */
	public static float getHostFloat(int encodedValue) {
		int exponentCode = extractExponentCode(encodedValue);
		int signBit = extractSignBit(encodedValue);
		int significandCode = extractSignificandCode(encodedValue);

		// Original library ignores the MSB of the significand (assumes normalized value)
		// while converting into IEEE 754 binary32 (where MSB is implicit and not stored)
		int fraction = significandCode & FRACTION_MASK;
		if (exponentCode == 0 && signBit == 0 && fraction == 0) {
			return 0.0f;
		}

		// IEEE 754 binary32 (SEEEEEEE EFFFFFFF FFFFFFFF FFFFFFFF)
		int floatBits = fraction << 0; // Assumes FRACTION_SIZE == 23 (no conversion)
		floatBits |= (exponentCode - EXPONENT_BIAS + 127) << 23;
		floatBits |= signBit << 31;
		return Float.intBitsToFloat(floatBits);
	}

	/**
	 * Convert host's float into encoded Motorola Fast Floating Point (MFFP) value
	 */
	public static int getEncoding(float floatValue) {
		// IEEE 754 binary32 (SEEEEEEE EFFFFFFF FFFFFFFF FFFFFFFF)
		int floatBits = Float.floatToRawIntBits(floatValue);
		int fraction = (floatBits >>> 0) & ((1 << 23) - 1);
		int scale = ((floatBits >>> 23) & ((1 << 8) - 1)) - 127;
		boolean sign = ((floatBits >>> 31) & 1) != 0;
		
		// Original library IEEE 754 binary32 to Motorola FFP conversion rules
		if (Float.isInfinite(floatValue)) {
			return sign ? MAX_NEGATIVE_VALUE : MAX_POSITIVE_VALUE;
		}
		if (Float.isNaN(floatValue)) {
			return ZERO_VALUE;
		}
		// Also handles zero, subnormal, and scale underflow/overflow
		return encodeMotorolaFfp(sign, fraction, scale);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new MotorolaFfpDataType(dtm);
	}

	@Override
	public int getLength() {
		return BYTE_SIZE;
	}

	@Override
	public String getDescription() {
		return "Motorola Fast Floating Point (MFFP)";
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Float.class;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		int size = getLength(); // Use type length (ignore length argument)
		byte[] bytes = new byte[size];
		if (buf.getBytes(bytes, 0) != size) {
			return null;
		}
		int encodedValue = 0;
		for (int i = 0; i < size; i++) {
			encodedValue = (encodedValue << 8) | (bytes[i] & 0xff);
		}
		// No swap (Motorola FFP is always big-endian)
		float floatValue = getHostFloat(encodedValue);
		return Float.valueOf(floatValue);
	}

	@Override
	public boolean isEncodable() {
		return true;
	}

	@Override
	public byte[] encodeValue(Object value, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		try {
			int size = getLength();
			if (length != -1 && length != size) {
				throw new DataTypeEncodeException("Length mismatch", value, this);
			}
			if (!(value instanceof Number)) {
				throw new DataTypeEncodeException(name + " requires Number type", value, this);
			}
			float floatValue = ((Number) value).floatValue();
			int encodedValue = getEncoding(floatValue);
			byte[] bytes = new byte[size];
			for (int i = 0; i < size; ++i) {
				bytes[size - i - 1] = (byte) encodedValue;
				encodedValue >>>= 8;
			}
			return bytes;
		}
		catch (DataTypeEncodeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new DataTypeEncodeException(value, this, e);
		}
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		Object obj = getValue(buf, settings, length);
		if (obj == null) {
			return "??";
		}
		return obj.toString();
	}

	@Override
	public byte[] encodeRepresentation(String repr, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		try {
			int size = getLength();
			if (length != -1 && length != size) {
				throw new DataTypeEncodeException("Length mismatch", repr, this);
			}
			Float value = Float.valueOf(repr);
			return encodeValue(value, buf, settings, length);
		}
		catch (DataTypeEncodeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new DataTypeEncodeException(repr, this, e);
		}
	}

}
