class Dns::Query
  attr_accessor :id
  attr_accessor :flags
  attr_accessor :questions
  attr_accessor :answers
  attr_accessor :authorities
  attr_accessor :additionals

  def initialize
    @id = 0
    @flags = 0
    @questions = []
    @answers = []
    @authorities = []
    @additionals = []
  end

  def mode= mode
    @flags = (@flags & 0b0111_1111_1111_1111) | (Dns::MODES.index(mode) << 15)
  end

  def mode
    Dns::MODES[((@flags & 0b1000_0000_0000_0000) >> 15)]
  end

  def opcode= opcode
    @flags = (@flags & 0b1000_0111_1111_1111) | (Dns::OPCODES.index(opcode) << 14)
  end

  def opcode
    Dns::OPCODES[(@flags & 0b0111_1000_0000_0000) >> 14]
  end

  def authoritative= authoritative
    @flags = (@flags & 0xb0000_0100_0000_0000) | ((authoritative ? 1 : 0) << 10)
  end

  def authoritative?
    ((@flags & 0b0000_0100_0000_0000) >> 10) == 1
  end

  def truncation= truncation
    @flags = (@flags & 0xb0000_0010_0000_0000) | ((truncation ? 1 : 0) << 9)
  end

  def truncation?
    ((@flags & 0b0000_0010_0000_0000) >> 9) == 1
  end

  def recursion_desired= recursion_desired
    @flags = (@flags & 0xb0000_0001_0000_0000) | ((recursion_desired ? 1 : 0) << 8)
  end

  def recursion_desired?
    ((@flags & 0b0000_0001_0000_0000) >> 8) == 1
  end

  def recursion_available= recursion_available
    @flags = (@flags & 0xb0000_0000_1000_0000) | ((recursion_available ? 1 : 0) << 7)
  end

  def recursion_available?
    ((@flags & 0b0000_0000_1000_0000) >> 7) == 1
  end

  def zero= zero
    @flags = (@flags & 0b1111_1111_1000_1111) | (zero << 4)
  end

  def zero
    (@flags & 0b0000_0000_0111_0000) >> 4
  end

  def response_code= response_code
    @flags = (@flags & 0b1111_1111_1111_0000) | (Dns::RESPONSE_CODES.index(response_code) << 14)
  end

  def response_code
    Dns::RESPONSE_CODES[(@flags & 0b0000_0000_0000_1111) >> 0]
  end

  def to_data
    query = [id, @flags, questions.length, answers.length, authorities.length, additionals.length].pack('nnnnnn')
    [questions, answers, authorities, additionals].each do |records|
      records.each do |record|
        query << if record.is_a? String
          record
        else
          record.to_data
        end
      end
    end
    query
  end
end
