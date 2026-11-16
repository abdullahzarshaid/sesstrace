# Part C. Loaded with RUBYOPT=-r<this file>, outside the host file. Starts the standard Coverage library (lines and
# branches) before the library is loaded, and writes the result as JSON to the file named in WITNESS_OUT when Ruby exits.
require 'coverage'
require 'json'
Coverage.start(lines: true, branches: true)
at_exit do
  result = Coverage.result.select { |file, _| file.start_with?('/tmp/checkout/') }
  out = result.transform_values do |cov|
    { 'lines' => cov[:lines],
      'branches' => (cov[:branches] || {}).map { |b, targets| { 'branch' => b.map(&:to_s), 'targets' => targets.map { |t, n| { 'target' => t.map(&:to_s), 'count' => n } } } } }
  end
  File.write(ENV.fetch('WITNESS_OUT'), JSON.pretty_generate(out))
end
