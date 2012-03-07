class Dns::Question
  attr_accessor :name

  def initialize name='', type=0, klass=0
    @name = name
    self.type = type
    self.klass = klass
  end

  def type= type
    if type.is_a? Fixnum
      @type = type
    else
      @type = Dns::TYPES.index(type)
    end
  end

  def type
    Dns::TYPES[@type]
  end

  def klass= klass
    if klass.is_a? Fixnum
      @klass = klass
    else
      @klass = Dns::KLASSES.index(klass)
    end
  end

  def klass
    Dns::KLASSES[@klass]
  end

  def to_data
    question = ''
    @name.split('.').each do |w|
      question << [w.length, w].pack('Ca*')
    end
    question + [@type, @klass].pack('xnn')
  end

  class << self
    def parse data, index=0
      question = new
      pieces = []
      indexes = []
      loop do
        piece_length = data.unpack("x#{index}C").first
        if piece_length.zero?
          if indexes.empty?
            index += 1
            break
          else
            index = indexes.first
            indexes = []
            next
          end
        end
        if piece_length >> 6 == 0b11
          raise 'Pointer Loop' if indexes.include? index + 2
          indexes << index + 2
          index = data.unpack("x#{index}n").first & 0b0011_1111_1111_1111
        else
          index += 1
          pieces << data.unpack("x#{index}a#{piece_length}").first
          index += piece_length
        end
      end
      question.name = pieces.join('.')
      question.type = data.unpack("x#{index}n").first
      index += 2
      question.klass = data.unpack("x#{index}n").first
      index += 2
      [question, index]
    end
  end
end
