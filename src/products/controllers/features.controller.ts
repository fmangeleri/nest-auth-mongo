import {
  Controller,
  Get,
  Param,
  Post,
  Body,
  Put,
  Delete,
  ParseIntPipe,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';

import { FeaturesService } from '../services/features.service';
import { CreateFeatureDto, UpdateFeatureDto } from '../dtos/features.dtos';
import { MongoIdPipe } from 'src/common/mongoId.pipe';

@ApiTags('Features')
@Controller('Features')
export class FeaturesController {
  constructor(private FeaturesService: FeaturesService) {}

  @Get()
  async findAll() {
    return await this.FeaturesService.findAll();
  }

  @Get(':id')
  async get(@Param('id', MongoIdPipe) id: string) {
    return await this.FeaturesService.findOne(id);
  }

  @Post()
  async create(@Body() payload: CreateFeatureDto) {
    return await this.FeaturesService.create(payload);
  }

  // @Put(':id')
  // update(
  //   @Param('id', ParseIntPipe) id: number,
  //   @Body() payload: UpdateFeatureDto,
  // ) {
  //   return this.FeaturesService.update(id, payload);
  // }

  // @Delete(':id')
  // remove(@Param('id', ParseIntPipe) id: number) {
  //   return this.FeaturesService.remove(+id);
  // }
}
