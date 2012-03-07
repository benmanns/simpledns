class Dns::Answer
  attr_accessor :name
  attr_accessor :time_to_live
  attr_accessor :data

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
    answer = ''
    @name.split('.').each do |w|
      question << [w.length, w].pack('Ca*')
    end
    answer + [@type, @klass, @time_to_live, @data.length, @data].pack('xnnNna*')
  end

  class << self
    def parse data, index=0
      answer = new
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
            break
          end
        elsif piece_length >> 6 == 0b11
          raise 'Pointer Loop' if indexes.include? index + 2
          indexes << index + 2
          index = data.unpack("x#{index}n").first & 0b0011_1111_1111_1111
        else
          index += 1
          pieces << data.unpack("x#{index}a#{piece_length}").first
          index += piece_length
        end
      end
      answer.name = pieces.join('.')
      answer.type = data.unpack("x#{index}n").first
      index += 2
      answer.klass = data.unpack("x#{index}n").first
      index += 2
      answer.time_to_live = data.unpack("x#{index}N").first
      index += 4
      data_length = data.unpack("x#{index}n").first
      index += 2
      answer.data = data.unpack("x#{index}a#{data_length}").first
      index += data_length
      [answer, index]
    end
  end
end
