FROM ruby:2.3.1

RUN mkdir /automator
WORKDIR /automator

COPY Gemfile* ./
RUN bundle install

COPY * ./

ENTRYPOINT ["/automator/automator.rb"]

CMD []